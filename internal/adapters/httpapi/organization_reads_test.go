package httpapi

import (
	"net/http/httptest"
	"testing"
)

func TestOrganizationReadActivityHeader(t *testing.T) {
	for _, activity := range []string{"foreground", "background", "invalid", ""} {
		r := httptest.NewRequest("GET", "/orgs/11111111-1111-4111-8111-111111111111/members", nil)
		r.SetPathValue("orgID", "11111111-1111-4111-8111-111111111111")
		r.Header.Set("X-Umir-Session", "synthetic-session")
		r.Header.Set("X-Umir-Activity", activity)
		_, err := organizationListRequest(httptest.NewRecorder(), r)
		if valid := activity == "foreground" || activity == "background"; (err == nil) != valid {
			t.Fatalf("activity header %q: %v", activity, err)
		}
	}
}
