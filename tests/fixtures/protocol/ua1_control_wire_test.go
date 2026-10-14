package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func ua1WireOwner(t *testing.T) (ua1ControlOwner, *UA1ControlWireHandler, *atomic.Bool) {
	t.Helper()
	o := newUA1ControlOwner(t)
	ready := &atomic.Bool{}
	ready.Store(true)
	h, err := NewUA1ControlWireHandler(HandlerOptions{Project: "umir-backend-000000000000000000000000", Credential: strings.Repeat("a", 64), BinarySHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), Clock: o.clock, Store: o.r.Store, Ready: func(context.Context) bool { return ready.Load() }}, o.controls)
	if err != nil {
		t.Fatal(err)
	}
	return o, h, ready
}

func ua1WireRequest(t *testing.T, o ua1ControlOwner, action string, id string, arm *UA1ControlArm) UA1ControlWireRequest {
	t.Helper()
	return UA1ControlWireRequest{Version: 1, Supplement: UA1ControlWireSupplement, BindingSHA256: UA1ControlWireBindingSHA256, Project: "umir-backend-000000000000000000000000", RequestID: ua1ControlID(t), Owner: "auth", Expected: o.identity(), Action: action, ControlID: id, Arm: arm}
}

func ua1WireCall(t *testing.T, h http.Handler, value UA1ControlWireRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, UA1ControlWirePath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	return res
}

func TestUA1ControlWireArmReadCancelAndExactReplay(t *testing.T) {
	o, h, ready := ua1WireOwner(t)
	id := ua1ControlID(t)
	request := ua1WireRequest(t, o, "control.arm", "", &UA1ControlArm{ControlID: id, Point: "before-process-mail", LifetimeMS: 30000})
	first := ua1WireCall(t, h, request)
	if first.Code != 200 || validateUA1ControlWire("Response", first.Body.Bytes()) != nil {
		t.Fatal("valid arm refused", first.Code, first.Body.String())
	}
	c := o.clock.Read()
	if code := o.clock.Set(c.InstanceID, c.Generation, c.Instant); code != "" {
		t.Fatal(code)
	}
	replay := ua1WireCall(t, h, request)
	if replay.Code != 200 || !bytes.Equal(first.Body.Bytes(), replay.Body.Bytes()) {
		t.Fatal("cached response relabelled after clock progress")
	}
	changed := request
	changed.Expected = o.identity()
	if conflict := ua1WireCall(t, h, changed); conflict.Code != 409 || !strings.Contains(conflict.Body.String(), "CorrelationConflict") {
		t.Fatal("changed request ID did not conflict")
	}
	ready.Store(false)
	read := ua1WireCall(t, h, ua1WireRequest(t, o, "control.read", id, nil))
	if read.Code != 200 {
		t.Fatal("read disappeared after readiness loss", read.Code)
	}
	if res := ua1WireCall(t, h, ua1WireRequest(t, o, "control.cancel", id, nil)); res.Code != 200 || !strings.Contains(res.Body.String(), "cancelled") {
		t.Fatal("cancel failed", res.Code)
	}
	newArm := ua1WireRequest(t, o, "control.arm", "", &UA1ControlArm{ControlID: ua1ControlID(t), Point: "before-process-mail", LifetimeMS: 100})
	failure := ua1WireCall(t, h, newArm)
	if failure.Code != 503 {
		t.Fatal("unready arm accepted")
	}
	ready.Store(true)
	if retry := ua1WireCall(t, h, newArm); retry.Code != failure.Code || !bytes.Equal(retry.Body.Bytes(), failure.Body.Bytes()) {
		t.Fatal("retained error silently retried")
	}
}

func TestUA1ControlWireBodyAndIdentityAdmission(t *testing.T) {
	o, h, _ := ua1WireOwner(t)
	valid := ua1WireRequest(t, o, "control.arm", "", &UA1ControlArm{ControlID: ua1ControlID(t), Point: "before-process-mail", LifetimeMS: 100})
	for _, mutate := range []func(*UA1ControlWireRequest){
		func(r *UA1ControlWireRequest) { r.Project = "umir-backend-111111111111111111111111" },
		func(r *UA1ControlWireRequest) { r.BindingSHA256 = strings.Repeat("d", 64) },
		func(r *UA1ControlWireRequest) { r.Expected.ClockGeneration = "2" },
		func(r *UA1ControlWireRequest) { r.Expected.InstanceID = "99999999-9999-4999-8999-999999999999" },
	} {
		request := valid
		request.RequestID = ua1ControlID(t)
		mutate(&request)
		if res := ua1WireCall(t, h, request); res.Code == 200 {
			t.Fatal("foreign input accepted")
		}
	}
	body, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(append([]byte{}, body[:len(body)-1]...), []byte(",\"payload\":\"private\"}")...), append(append([]byte{}, body[:len(body)-1]...), []byte(",\"version\":1}")...), append(append([]byte{}, body...), []byte(" {}")...)} {
		if validateUA1ControlWire("Request", bad) == nil {
			t.Fatal("open/duplicate/trailing input accepted")
		}
	}
	for _, path := range []string{UA1ControlWirePath + "/", UA1ControlWirePath + "?x=1", "/ua1-mail-controls/%76%31"} {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code == 200 {
			t.Fatal("alternate path accepted")
		}
	}
	for _, auth := range [][]string{nil, {"Bearer " + strings.Repeat("d", 64)}, {"Bearer " + strings.Repeat("a", 64), "Bearer " + strings.Repeat("a", 64)}} {
		req := httptest.NewRequest(http.MethodPost, UA1ControlWirePath, bytes.NewReader(body))
		for _, s := range auth {
			req.Header.Add("Authorization", s)
		}
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code != 401 {
			t.Fatal("server did not deny credential", res.Code)
		}
	}
	o.controls.mu.Lock()
	count := len(o.controls.records)
	o.controls.mu.Unlock()
	if count != 0 {
		t.Fatal("admission failure armed a control")
	}
}

func TestUA1ControlWireActualBusinessBodyAndActor(t *testing.T) {
	o, h, _ := ua1WireOwner(t)
	owner, err := o.r.Handler(map[string]string{"gateway": strings.Repeat("a", 64), "serving": strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := o.controls.WrapBusiness(o.r.Accounts, owner)
	if err != nil {
		t.Fatal(err)
	}
	in := application.CreateInvitationInput{CommandID: "wire-created", Email: "wire@umir.invalid", Assignments: []domain.InviteAssignment{{RestaurantID: o.org.RestaurantIDs[0], Roles: []string{"Waiter"}}}}
	body, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	sel := UA1CommandSelector{OperationID: "createInvitation", CommandID: in.CommandID, ActorID: o.session.User.UserID, OrgID: o.org.OrgID, BodySHA256: SHA(body)}
	id := ua1ControlID(t)
	if res := ua1WireCall(t, h, ua1WireRequest(t, o, "control.arm", "", &UA1ControlArm{ControlID: id, Point: "storage-before-commit", LifetimeMS: 30000, Command: &sel})); res.Code != 200 {
		t.Fatal("arm failed", res.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/internal/auth/v1/public/orgs/"+string(o.org.OrgID)+"/invitations", bytes.NewReader(body))
	req.Header.Set("X-Umir-Service-Key", strings.Repeat("a", 64))
	req.Header.Set("X-Umir-Session", o.session.Token)
	req.Header.Set("X-Umir-CSRF-Token", o.session.CSRFToken)
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	wrapped.ServeHTTP(res, req)
	if res.Code != 503 {
		t.Fatal("actual HTTP command bypassed control", res.Code, res.Body.String())
	}
	read := ua1WireCall(t, h, ua1WireRequest(t, o, "control.read", id, nil))
	if read.Code != 200 || !strings.Contains(read.Body.String(), "writer-not-called") || strings.Contains(read.Body.String(), o.session.Token) || strings.Contains(read.Body.String(), in.Email) {
		t.Fatal("actual body/actor effect or privacy missing")
	}
	got, err := o.r.Store.Load(context.Background())
	if err != nil || len(got.Snapshot().MailJobs) != 0 {
		t.Fatal("precommit control mutated authority")
	}
}
