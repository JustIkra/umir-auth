package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
)

func TestPasswordLimitResponsePreservesRevocationAndDelay(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(fmt.Sprint(revoked), func(t *testing.T) {
			w := httptest.NewRecorder()
			failure(w, fmt.Errorf("wrapped: %w", &application.PasswordChangeLimitError{RetryAfter: 60 * time.Second, SessionRevoked: revoked}))
			var result struct {
				Code           string `json:"code"`
				Outcome        string `json:"outcome"`
				SessionRevoked *bool  `json:"sessionRevoked"`
				Details        struct {
					RetryAfter int `json:"retryAfterSeconds"`
				} `json:"details"`
			}
			if json.Unmarshal(w.Body.Bytes(), &result) != nil || w.Code != 429 || result.Code != "PasswordChangeRateLimited" || result.Outcome != "not_committed" || result.SessionRevoked == nil || *result.SessionRevoked != revoked || result.Details.RetryAfter != 60 || w.Header().Get("Retry-After") != "60" {
				t.Fatalf("password limit projection lost revocation or delay: status=%d revokedPresent=%t delay=%d", w.Code, result.SessionRevoked != nil, result.Details.RetryAfter)
			}
		})
	}
}
