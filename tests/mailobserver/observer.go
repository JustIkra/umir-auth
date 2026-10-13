package mailobserver

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/JustIkra/umir-auth/internal/application"
)

type Transport interface {
	Deliver(context.Context, application.MailDelivery, []byte) application.DeliveryResult
}
type Observer struct{ Transport Transport }

func (o Observer) Deliver(ctx context.Context, d application.MailDelivery, message []byte) application.DeliveryResult {
	if o.Transport == nil || !identifier.MatchString(string(d.JobID)) || d.JobID != d.Mail.IssuanceID || !identifier.MatchString(string(d.Mail.ChallengeID)) || bytes.Contains(message, []byte("X-Umir-Fixture-")) {
		return application.DeliveryResult{Permanent: true, Code: "fixture_correlation_invalid"}
	}
	if !synthetic(d.Mail.Email) {
		return application.DeliveryResult{Permanent: true, Code: "fixture_privacy_violation"}
	}
	var envelope bytes.Buffer
	if _, err := fmt.Fprintf(&envelope, "X-Umir-Fixture-Job-ID: %s\r\nX-Umir-Fixture-Challenge-ID: %s\r\n", d.JobID, d.Mail.ChallengeID); err != nil {
		return application.DeliveryResult{Permanent: true, Code: "fixture_correlation_invalid"}
	}
	if _, err := envelope.Write(message); err != nil {
		return application.DeliveryResult{Permanent: true, Code: "fixture_correlation_invalid"}
	}
	defer clear(envelope.Bytes())
	return o.Transport.Deliver(ctx, d, envelope.Bytes())
}

var identifier = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func synthetic(s string) bool { return strings.HasSuffix(strings.ToLower(s), ".invalid") }
