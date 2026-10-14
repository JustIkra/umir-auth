package mailadapter

import (
	"context"
	"mime"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func testInvitationLink() application.MailDelivery {
	at := testCodeMail().CreatedAt
	id := domain.EntityID("00000000-0000-4000-8000-000000000005")
	return application.MailDelivery{JobID: "00000000-0000-4000-8000-000000000008", Link: &application.InvitationLinkMail{InvitationID: id, Email: "invitee@umir.invalid", URL: "https://app.umir.invalid/invite/" + string(id), CreatedAt: at, ExpiresAt: at.Add(7 * 24 * time.Hour)}}
}

func TestUA1InvitationLinkMIMEKeepsJobIdentityAndCopy(t *testing.T) {
	template, err := NewRegistrationTemplate(validRegistrationMailConfig())
	if err != nil {
		t.Fatal(err)
	}
	delivery := testInvitationLink()
	sender := &RegistrationSMTP{smtp: &SMTP{from: mail.Address{Address: "sender@umir.invalid"}, domain: "umir.invalid"}, template: template}
	message, err := sender.linkMessage(delivery)
	if err != nil {
		t.Fatal(err)
	}
	text := string(message)
	for _, expected := range []string{"Message-ID: <invitation." + string(delivery.JobID) + "@umir.invalid>", "Content-Type: multipart/related"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing MIME field %q", expected)
		}
	}
	rendered, err := template.RenderInvitationLink(*delivery.Link)
	if err != nil || !strings.Contains(rendered.Text, delivery.Link.URL) || !strings.Contains(rendered.HTML, "Открыть приглашение") || !strings.Contains(rendered.HTML, "МСК") || !strings.Contains(rendered.HTML, "cid:"+registrationLogoContentID) {
		t.Fatal("invitation rendering omitted URL, expiry, action or existing brand")
	}
	if strings.Contains(rendered.HTML, "GroupedCode") || strings.Contains(rendered.Text, "код: ") {
		t.Fatal("link message reused an OTP payload")
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(strings.Split(strings.Split(text, "Subject: ")[1], "\r\n")[0])
	if err != nil || subject != "Приглашение в «Ровный ход»" {
		t.Fatal("invalid invitation subject")
	}
	for _, url := range []string{"javascript:alert(1)", "https://app.umir.invalid/wrong", "https://user:password@app.umir.invalid/invite/" + string(delivery.Link.InvitationID)} {
		bad := *delivery.Link
		bad.URL = url
		if _, err := template.RenderInvitationLink(bad); err == nil {
			t.Fatal("unsafe invitation URL rendered")
		}
	}
}

func TestUA1InvitationLinkSenderExpiryAndUnknown(t *testing.T) {
	delivery := testInvitationLink()
	transport := &ua1MessageTransport{result: application.DeliveryResult{Unknown: true}}
	smtp := &SMTP{from: mail.Address{Address: "sender@umir.invalid"}, domain: "umir.invalid"}
	sender, err := NewRegistrationSMTP(smtp, validRegistrationMailConfig(), func() time.Time { return delivery.Link.CreatedAt }, transport)
	if err != nil {
		t.Fatal(err)
	}
	if result := sender.Send(context.Background(), delivery); !result.Unknown || result.Success || result.Permanent || transport.calls != 1 {
		t.Fatal("link unknown result was lost or not dispatched")
	}
	sender.now = func() time.Time { return delivery.Link.ExpiresAt }
	if result := sender.Send(context.Background(), delivery); !result.Permanent || transport.calls != 1 {
		t.Fatal("expired link reached SMTP")
	}
}

type ua1MessageTransport struct {
	result application.DeliveryResult
	calls  int
}

func (s *ua1MessageTransport) Deliver(_ context.Context, _ application.MailDelivery, message []byte) application.DeliveryResult {
	if len(message) > 0 {
		s.calls++
	}
	return s.result
}
