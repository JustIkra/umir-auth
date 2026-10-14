package invitationurl

import (
	"testing"

	"github.com/JustIkra/umir-auth/internal/application"
)

func TestTrustedOriginGuard(t *testing.T) {
	p := Policy{}
	for _, origin := range []string{"", "https://user@ui.invalid", "https://ui.invalid/path", "https://ui.invalid?", "https://ui.invalid#", "https://ui.invalid#fragment", "http://ui.invalid", "https://ui.invalid\r\n"} {
		if result, err := p.Origin(application.InvitationMailOptions{FrontendOrigin: origin, AllowLoopbackHTTP: true}); err == nil || result != "" {
			t.Fatalf("invalid trusted origin accepted: %q", origin)
		}
	}
	for _, origin := range []string{"https://ui.invalid", "http://localhost:18980", "http://127.1.2.3:18980", "http://[::1]:18980"} {
		if result, err := p.Origin(application.InvitationMailOptions{FrontendOrigin: origin, AllowLoopbackHTTP: true}); err != nil || result != origin {
			t.Fatalf("valid trusted origin rejected: %q", origin)
		}
	}
}
