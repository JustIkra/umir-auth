package profiles

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/tests/fixtures/protocol"
)

func TestRefusalProfileReportIdentityAndReplay(t *testing.T) {
	_, clock := profileOptions(t)
	owner := &Owner{binding: protocol.ProfileBinding{Project: "umir-backend-000000000000000000000000", Profile: "auth-corrupt-json", Owner: "auth", InstanceID: clock.Read().InstanceID, BinarySHA256: strings.Repeat("a", 64), ConfigSHA256: strings.Repeat("b", 64), FixtureSHA256: strings.Repeat("c", 64), ProfileConfigSHA256: strings.Repeat("d", 64), ProfileContractIdentity: protocol.ProfileIdentity}, clock: clock, credential: strings.Repeat("e", 64), refused: true, opened: time.Now(), cache: map[string]cached{}}
	input := protocol.ProfileRequest{Amendment: protocol.ProfileAmendment, Project: owner.binding.Project, Profile: owner.binding.Profile, RequestID: "77777777-7777-4777-8777-777777777777", ExpectedInstanceID: clock.Read().InstanceID, ExpectedGeneration: "1", Action: "report"}
	call := func(body []byte, key string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("POST", protocol.ProfilePath, strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		owner.ServeHTTP(w, req)
		return w
	}
	b := mustJSON(t, input)
	first := call(b, owner.credential)
	if first.Code != 200 {
		t.Fatalf("report: %d %s", first.Code, first.Body.String())
	}
	var report protocol.ProfileReport
	if json.Unmarshal(first.Body.Bytes(), &report) != nil || report.Admission != "refused" || report.NormalReady || report.BusinessHandlerCreated || report.Error == nil || *report.Error != "StorageUnavailable" {
		t.Fatal("fabricated admission")
	}
	repeated := call(b, owner.credential)
	if repeated.Code != 200 || repeated.Body.String() != first.Body.String() {
		t.Fatal("replay drift")
	}
	changed := input
	changed.ExpectedGeneration = "2"
	if w := call(mustJSON(t, changed), owner.credential); w.Code != 409 {
		t.Fatal("request conflict", w.Code)
	}
	changed.RequestID = "88888888-8888-4888-8888-888888888888"
	if w := call(mustJSON(t, changed), owner.credential); w.Code != 409 {
		t.Fatal("stale generation", w.Code)
	}
	changed = input
	changed.Project = "umir-backend-111111111111111111111111"
	if w := call(mustJSON(t, changed), owner.credential); w.Code != 403 {
		t.Fatal("foreign project", w.Code)
	}
	if w := call(b, "wrong"); w.Code != 401 {
		t.Fatal("wrong control", w.Code)
	}
	duplicate := strings.Replace(string(b), `"action":"report"`, `"action":"report","action":"report"`, 1)
	if w := call([]byte(duplicate), owner.credential); w.Code != 400 {
		t.Fatal("duplicate JSON", w.Code)
	}
	if w := call(append(b, []byte(` {}`)...), owner.credential); w.Code != 400 {
		t.Fatal("trailing JSON", w.Code)
	}
}
