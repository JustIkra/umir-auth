package smtpsink

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "api.telegram.org test cert"},
		DNSNames:              []string{"api.telegram.org", "localhost"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return certificate, roots
}

type smtpTestServer struct {
	port         int
	messages     chan string
	auth         chan string
	authCommands chan string
	rcpt         chan string
}

type smtpAuthScript struct {
	rejectCode int
}

func newSMTPTestServer(t *testing.T, mode string, finalCode int) (*smtpTestServer, *x509.CertPool) {
	postTLSAuth := []string(nil)
	if mode == "starttls" {
		postTLSAuth = []string{"PLAIN"}
	}
	return newSMTPTestServerWithAuth(t, mode, finalCode, []string{"PLAIN"}, postTLSAuth, nil)
}

func newSMTPTestServerWithAuth(t *testing.T, mode string, finalCode int, preTLSAuth, postTLSAuth []string, authScript *smtpAuthScript) (*smtpTestServer, *x509.CertPool) {
	t.Helper()
	certificate, roots := testCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &smtpTestServer{
		port:         smtpTestPort(t, listener),
		messages:     make(chan string, 1),
		auth:         make(chan string, 1),
		authCommands: make(chan string, 2),
		rcpt:         make(chan string, 1),
	}
	t.Cleanup(func() { closeQuietly(listener) })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go server.handle(t, conn, mode, finalCode, certificate, preTLSAuth, postTLSAuth, authScript)
		}
	}()
	return server, roots
}

func (s *smtpTestServer) handle(t *testing.T, conn net.Conn, mode string, finalCode int, certificate tls.Certificate, preTLSAuth, postTLSAuth []string, authScript *smtpAuthScript) {
	defer closeQuietly(conn)
	if mode == "tls" || mode == "drop-reply" {
		conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	}
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	write := func(response string) bool {
		if _, err := io.WriteString(writer, response+"\r\n"); err != nil {
			return false
		}
		return writer.Flush() == nil
	}
	if !write("220 smtp.example.test ready") {
		return
	}
	authCapabilities := preTLSAuth
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		command := strings.TrimSpace(line)
		fields := strings.Fields(command)
		if len(fields) == 0 {
			return
		}
		switch strings.ToUpper(fields[0]) {
		case "EHLO", "HELO":
			if mode == "ehlo-fail" {
				return
			}
			if mode == "no-starttls" {
				if !write("250 smtp.example.test") {
					return
				}
			} else {
				if !write("250-smtp.example.test") {
					return
				}
				if mode == "starttls" && !write("250-STARTTLS") {
					return
				}
				if !writeAuthExtension(write, authCapabilities) {
					return
				}
			}
		case "STARTTLS":
			if mode != "starttls" || !write("220 begin TLS") {
				return
			}
			secured := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
			conn = secured
			reader = bufio.NewReader(conn)
			writer = bufio.NewWriter(conn)
			mode = "starttls-after"
			authCapabilities = postTLSAuth
		case "AUTH":
			s.authCommands <- strings.ToUpper(strings.Join(fields[:2], " "))
			if len(fields) >= 2 && strings.EqualFold(fields[1], "PLAIN") && containsMechanism(authCapabilities, "PLAIN") {
				if len(fields) != 3 {
					if !write("501 invalid PLAIN response") {
						return
					}
					continue
				}
				decoded, decodeErr := base64.StdEncoding.DecodeString(fields[2])
				if decodeErr == nil {
					if authScript != nil && authScript.rejectCode > 0 {
						s.auth <- string(decoded)
						if !write(fmt.Sprintf("%d authentication rejected", authScript.rejectCode)) {
							return
						}
						continue
					}
					s.auth <- string(decoded)
				}
				if !write("235 authenticated") {
					return
				}
				continue
			}
			if len(fields) == 2 && strings.EqualFold(fields[1], "LOGIN") && containsMechanism(authCapabilities, "LOGIN") {
				if !write("334 " + base64.StdEncoding.EncodeToString([]byte("Username:"))) {
					return
				}
				username, readErr := reader.ReadString('\n')
				if readErr != nil {
					return
				}
				if !write("334 " + base64.StdEncoding.EncodeToString([]byte("Password:"))) {
					return
				}
				password, readErr := reader.ReadString('\n')
				if readErr != nil {
					return
				}
				userBytes, userErr := base64.StdEncoding.DecodeString(strings.TrimSpace(username))
				passBytes, passErr := base64.StdEncoding.DecodeString(strings.TrimSpace(password))
				if userErr != nil || passErr != nil {
					if !write("501 invalid LOGIN response") {
						return
					}
					continue
				}
				s.auth <- string(userBytes) + "\x00" + string(passBytes)
				code := 235
				if authScript != nil && authScript.rejectCode > 0 {
					code = authScript.rejectCode
				}
				if !write(fmt.Sprintf("%d authenticated", code)) {
					return
				}
				continue
			}
			if !write("504 unsupported authentication mechanism") {
				return
			}
		case "MAIL":
			if !write("250 sender accepted") {
				return
			}
		case "RCPT":
			if len(fields) > 1 {
				s.rcpt <- strings.TrimPrefix(fields[1], "TO:")
			}
			if finalCode >= 400 {
				if !write(fmt.Sprintf("%d recipient rejected", finalCode)) {
					return
				}
				return
			}
			if !write("250 recipient accepted") {
				return
			}
		case "DATA":
			if !write("354 continue") {
				return
			}
			var message strings.Builder
			for {
				part, readErr := reader.ReadString('\n')
				if readErr != nil {
					return
				}
				if strings.TrimSpace(part) == "." {
					break
				}
				if _, err := message.WriteString(part); err != nil {
					return
				}
			}
			s.messages <- message.String()
			if mode == "drop-reply" {
				return
			}
			if !write("250 accepted") {
				return
			}
			return
		case "QUIT":
			if !write("221 bye") {
				return
			}
			return
		default:
			if !write("250 ok") {
				return
			}
		}
	}
}

func writeAuthExtension(write func(string) bool, mechanisms []string) bool {
	if len(mechanisms) == 0 {
		return write("250 smtp.example.test")
	}
	return write("250 AUTH " + strings.Join(mechanisms, " "))
}

func containsMechanism(mechanisms []string, wanted string) bool {
	for _, mechanism := range mechanisms {
		if strings.EqualFold(mechanism, wanted) {
			return true
		}
	}
	return false
}

func smtpTestPort(t *testing.T, listener net.Listener) int {
	t.Helper()
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("SMTP test listener has address type %T", listener.Addr())
	}
	return address.Port
}

func New(t *testing.T, mode string, finalCode int) (*smtpTestServer, *x509.CertPool) {
	return newSMTPTestServer(t, mode, finalCode)
}
func (s *smtpTestServer) Port() int               { return s.port }
func (s *smtpTestServer) Messages() <-chan string { return s.messages }
func closeQuietly(c io.Closer) {
	if err := c.Close(); err != nil {
		return
	}
}
