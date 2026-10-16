package mailadapter

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
)

func TestAcceptedSMTPDropReplyRemainsUnknown(t *testing.T) {
	server, roots := newSMTPTestServer(t, "drop-reply", 250)
	config := validSMTPConfig()
	config.Port = server.port
	config.TLSMode = "tls"
	config.RootCAs = roots
	transport, err := NewSMTP(config)
	if err != nil {
		t.Fatal(err)
	}
	code := testCodeMail()
	sender, err := NewRegistrationSMTP(transport, validRegistrationMailConfig(), func() time.Time { return code.CreatedAt }, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := sender.Send(context.Background(), application.MailDelivery{Mail: code})
	if result.Success || result.Permanent || !result.Unknown {
		t.Fatal("accepted-but-unconfirmed SMTP reply was fabricated")
	}
	select {
	case <-server.messages:
	default:
		t.Fatal("test never accepted SMTP DATA")
	}
}

func dialTestSMTP(t *testing.T, port int) application.DeliveryResult {
	t.Helper()
	config := validSMTPConfig()
	config.Port = port
	config.TLSMode = "starttls"
	transport, err := NewSMTP(config)
	if err != nil {
		t.Fatal(err)
	}
	return transport.send(context.Background(), "to@example.test", []byte("Subject: x\r\n\r\nx\r\n"))
}

// A failed dial sent nothing, so the job is retried (L2); a failure after the
// connection exists may have sent something, so it stays unknown.
func TestSMTPDialFailureRetriesAndLaterFailureStaysUnknown(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := closed.Addr().(*net.TCPAddr).Port
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if result := dialTestSMTP(t, port); result.Success || result.Permanent || result.Unknown {
		t.Fatalf("a refused connection is %+v; want a plain retry", result)
	}

	hangup, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := hangup.Close(); err != nil {
			t.Error(err)
		}
	})
	go func() {
		for {
			conn, err := hangup.Accept()
			if err != nil {
				return
			}
			if err := conn.Close(); err != nil {
				return
			}
		}
	}()
	if result := dialTestSMTP(t, hangup.Addr().(*net.TCPAddr).Port); result.Success || result.Permanent || !result.Unknown {
		t.Fatalf("a hang-up after connecting is %+v; want unknown", result)
	}
}
