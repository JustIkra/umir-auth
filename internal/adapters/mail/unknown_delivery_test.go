package mailadapter

import (
	"context"
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
