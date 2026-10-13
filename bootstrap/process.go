package bootstrap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	mail "github.com/JustIkra/umir-auth/internal/adapters/mail"
	"github.com/JustIkra/umir-auth/internal/adapters/runtimehttp"
	"github.com/JustIkra/umir-auth/internal/adapters/timezones"
)

type clock struct{ location *time.Location }

func (c clock) Now() time.Time { return time.Now().In(c.location) }

type config struct {
	PrivateAddress   string                      `json:"privateAddress"`
	StateFile        string                      `json:"stateFile"`
	SecretsDir       string                      `json:"secretsDir"`
	Initial          *InitialUser                `json:"initialUser"`
	PasswordFile     string                      `json:"passwordFile"`
	ServiceKeyFiles  map[string]string           `json:"serviceKeyFiles"`
	PeerKeyFiles     map[string]string           `json:"peerKeyFiles"`
	PeerURLs         map[string]string           `json:"peerURLs"`
	ZoneDataFile     string                      `json:"zoneDataFile"`
	ZoneDataVersion  string                      `json:"zoneDataVersion"`
	IsolatedHTTP     bool                        `json:"isolatedHTTP"`
	TLSCertFile      string                      `json:"tlsCertFile"`
	TLSKeyFile       string                      `json:"tlsKeyFile"`
	SMTP             mail.SMTPConfig             `json:"smtp"`
	RegistrationMail mail.RegistrationMailConfig `json:"registrationMail"`
	SMTPUsernameFile string                      `json:"smtpUsernameFile"`
	SMTPPasswordFile string                      `json:"smtpPasswordFile"`
	SMTPCAFile       string                      `json:"smtpCAFile"`
}

func Run(ctx context.Context, path string) (err error) {
	body, e := ReadPrivateFile(path, 1<<20)
	if e != nil {
		return e
	}
	var cfg config
	if e = DecodeStrict(body, &cfg); e != nil {
		return e
	}
	keys, e := readKeys(cfg.ServiceKeyFiles)
	if e != nil {
		return e
	}
	peerKeys, e := readKeys(cfg.PeerKeyFiles)
	if e != nil {
		return e
	}
	peers, e := runtimehttp.New(cfg.PeerURLs, peerKeys, cfg.IsolatedHTTP)
	if e != nil {
		return e
	}
	defer peers.Shutdown()
	data, e := os.ReadFile(cfg.ZoneDataFile)
	if e != nil {
		return e
	}
	zones, e := timezones.New(data, cfg.ZoneDataVersion)
	if e != nil {
		return e
	}
	password, e := ReadPrivateFile(cfg.PasswordFile, 128)
	if e != nil {
		return e
	}
	defer clear(password)
	location, e := time.LoadLocation("Europe/Moscow")
	if e != nil {
		return e
	}
	o := Options{StateFile: cfg.StateFile, SecretsDir: cfg.SecretsDir, Initial: cfg.Initial, Password: string(password), Clock: clock{location: location}, TimeZones: zones, Runtimes: peers, ServiceKeys: keys}
	runtime, e := Open(ctx, o)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, runtime.Close()) }()
	if e = peers.Bind(runtime.Accounts); e != nil {
		return e
	}
	handler, e := runtime.Handler(keys)
	if e != nil {
		return e
	}
	username, e := ReadPrivateFile(cfg.SMTPUsernameFile, 256)
	if e != nil {
		return e
	}
	defer clear(username)
	secret, e := ReadPrivateFile(cfg.SMTPPasswordFile, 256)
	if e != nil {
		return e
	}
	defer clear(secret)
	cfg.SMTP.Username = string(username)
	cfg.SMTP.Password = string(secret)
	if cfg.SMTPCAFile != "" {
		pem, e := os.ReadFile(cfg.SMTPCAFile)
		if e != nil {
			return e
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return errors.New("invalid SMTP CA")
		}
		cfg.SMTP.RootCAs = roots
	}
	smtp, e := mail.NewSMTP(cfg.SMTP)
	if e != nil {
		return e
	}
	sender, e := mail.NewRegistrationSMTP(smtp, cfg.RegistrationMail, o.Clock.Now, nil)
	if e != nil {
		return e
	}
	listener, e := net.Listen("tcp", cfg.PrivateAddress)
	if e != nil {
		return e
	}
	if !cfg.IsolatedHTTP {
		cert, e := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if e != nil {
			return errors.Join(e, listener.Close())
		}
		listener = tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}})
	}
	return runtime.Serve(ctx, listener, handler, sender)
}
func readKeys(refs map[string]string) (map[string]string, error) {
	keys := map[string]string{}
	for name, path := range refs {
		if !filepath.IsAbs(path) {
			return nil, errors.New("invalid credential reference")
		}
		b, e := ReadPrivateFile(path, 64)
		if e != nil {
			return nil, e
		}
		keys[name] = string(b)
		clear(b)
	}
	return keys, nil
}
