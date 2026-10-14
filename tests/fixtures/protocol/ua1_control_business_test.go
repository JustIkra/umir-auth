package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestUA1ControlBusinessBoundaryRejectsActualBodyAndAdmissionMismatches(t *testing.T) {
	for _, kind := range []string{"body", "session", "csrf", "service-key", "org", "actor-header"} {
		t.Run(kind, func(t *testing.T) {
			o, h, _ := ua1WireOwner(t)
			owner, err := o.r.Handler(map[string]string{"gateway": strings.Repeat("a", 64), "serving": strings.Repeat("b", 64)})
			if err != nil {
				t.Fatal(err)
			}
			wrapped, err := o.controls.WrapBusiness(o.r.Accounts, owner)
			if err != nil {
				t.Fatal(err)
			}
			in := application.CreateInvitationInput{CommandID: "boundary-created", Email: "boundary@umir.invalid", Assignments: []domain.InviteAssignment{{RestaurantID: o.org.RestaurantIDs[0], Roles: []string{"Waiter"}}}}
			body, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}
			sel := UA1CommandSelector{OperationID: "createInvitation", CommandID: in.CommandID, ActorID: o.session.User.UserID, OrgID: o.org.OrgID, BodySHA256: SHA(body)}
			if kind == "actor-header" {
				sel.ActorID = "99999999-9999-4999-8999-999999999999"
			}
			id := ua1ControlID(t)
			if res := ua1WireCall(t, h, ua1WireRequest(t, o, "control.arm", "", &UA1ControlArm{ControlID: id, Point: "storage-before-commit", LifetimeMS: 30000, Command: &sel})); res.Code != 200 {
				t.Fatal(res.Code)
			}
			if kind == "body" {
				in.Email = "different@umir.invalid"
				body, err = json.Marshal(in)
				if err != nil {
					t.Fatal(err)
				}
			}
			org := string(o.org.OrgID)
			if kind == "org" {
				org = "99999999-9999-4999-8999-999999999999"
			}
			req := httptest.NewRequest(http.MethodPost, "/internal/auth/v1/public/orgs/"+org+"/invitations", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Umir-Service-Key", strings.Repeat("a", 64))
			req.Header.Set("X-Umir-Session", o.session.Token)
			req.Header.Set("X-Umir-CSRF-Token", o.session.CSRFToken)
			switch kind {
			case "session":
				req.Header.Set("X-Umir-Session", "invalid")
			case "csrf":
				req.Header.Set("X-Umir-CSRF-Token", "invalid")
			case "service-key":
				req.Header.Set("X-Umir-Service-Key", strings.Repeat("d", 64))
			case "actor-header":
				req.Header.Set("X-Umir-Actor-ID", string(sel.ActorID))
			}
			res := httptest.NewRecorder()
			wrapped.ServeHTTP(res, req)
			if kind == "body" || kind == "actor-header" {
				if res.Code != 201 {
					t.Fatal("positive unrelated input was blocked", res.Code)
				}
			} else if res.Code < 400 {
				t.Fatal("real owner admitted invalid input", res.Code)
			}
			if o.read(t, id).Hits != 0 {
				t.Fatal("wrong actual body/actor/admission hit fault")
			}
			a, err := o.r.Store.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if kind == "body" || kind == "actor-header" {
				want = 1
			}
			if len(a.Snapshot().MailJobs) != want {
				t.Fatal("real job population does not match admission")
			}
		})
	}
}

type ua1FailingBody struct{ sent bool }

var errUA1BodyRead = errors.New("synthetic body read failure")

func (r *ua1FailingBody) Read(p []byte) (int, error) {
	if r.sent {
		return 0, io.EOF
	}
	r.sent = true
	return copy(p, []byte("{\"commandID\":\"incomplete")), errUA1BodyRead
}
func (*ua1FailingBody) Close() error { return nil }

func TestUA1ControlBusinessBoundaryPreservesUnderlyingReadFailure(t *testing.T) {
	o := newUA1ControlOwner(t)
	seen := false
	wrapped, err := o.controls.WrapBusiness(o.r.Accounts, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		seen = errors.Is(err, errUA1BodyRead)
	}))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/internal/auth/v1/public/orgs/"+string(o.org.OrgID)+"/invitations", &ua1FailingBody{})
	wrapped.ServeHTTP(httptest.NewRecorder(), req)
	if !seen {
		t.Fatal("observer converted read failure into a clean body")
	}
}
