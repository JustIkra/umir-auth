package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegistrationPrivateRequestSchema(t *testing.T) {
	req := httptest.NewRequest("POST", "/internal/auth/v1/public/email-challenges", nil)
	req.Pattern = "POST /internal/auth/v1/public/email-challenges"
	if err := schemaCheck(req, []byte(`{"commandID":"begin","email":"new@umir.invalid","purpose":"registration"}`)); err != nil {
		t.Fatal(err)
	}
	req.Pattern = "POST /internal/auth/v1/public/email-challenges/{challengeID}/complete"
	body := `{"commandID":"complete","challengeID":"00000000-0000-4000-8000-000000000001","proof":"01234567890123456789012345678901","purpose":"registration","displayName":"New User","password":"valid-password"}`
	if err := schemaCheck(req, []byte(body)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(body, `"password":"valid-password"`, `"password":"valid-password","newPassword":""`, 1), strings.Replace(body, `"displayName":"New User",`, "", 1)} {
		if err := schemaCheck(req, []byte(bad)); err == nil {
			t.Fatal("malformed registration accepted")
		}
	}
}
