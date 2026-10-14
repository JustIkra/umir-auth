package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type UA1SessionReader interface {
	Peek(context.Context, string) (application.SessionView, error)
}

type ua1ReplayedBody struct {
	*bytes.Reader
	original io.ReadCloser
	failure  error
}

func (b *ua1ReplayedBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if errors.Is(err, io.EOF) && b.failure != nil {
		err = b.failure
		b.failure = nil
	}
	return n, err
}
func (b *ua1ReplayedBody) Close() error { return b.original.Close() }

func (c *UA1MailControls) WrapBusiness(sessions UA1SessionReader, next http.Handler) (http.Handler, error) {
	if sessions == nil || next == nil {
		return nil, errors.New("invalid UA1 business boundary")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed, ok := ua1BusinessRoute(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		r.Body = &ua1ReplayedBody{Reader: bytes.NewReader(body), original: r.Body, failure: err}
		defer clear(body)
		tokens := r.Header.Values("X-Umir-Session")
		if err != nil || len(body) > 1<<20 || len(tokens) != 1 || checkDocument(body) != nil {
			next.ServeHTTP(w, r)
			return
		}
		var command struct {
			CommandID string `json:"commandID"`
		}
		if json.Unmarshal(body, &command) != nil {
			next.ServeHTTP(w, r)
			return
		}
		actor, err := sessions.Peek(r.Context(), tokens[0])
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		observed.CommandID = command.CommandID
		observed.ActorID = actor.User.UserID
		observed.BodySHA256 = SHA(body)
		ctx, err := c.CommandContext(r.Context(), observed, body)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	}), nil
}

func ua1BusinessRoute(r *http.Request) (UA1CommandSelector, bool) {
	if r.Method != http.MethodPost || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return UA1CommandSelector{}, false
	}
	p := strings.Split(r.URL.Path, "/")
	if len(p) != 8 && len(p) != 10 || p[0] != "" || p[1] != "internal" || p[2] != "auth" || p[3] != "v1" || p[4] != "public" || p[5] != "orgs" || p[7] != "invitations" || !uuidPattern.MatchString(p[6]) {
		return UA1CommandSelector{}, false
	}
	observed := UA1CommandSelector{OrgID: domain.EntityID(p[6]), OperationID: "createInvitation"}
	if len(p) == 10 {
		if !uuidPattern.MatchString(p[8]) || p[9] != "resend-link" {
			return UA1CommandSelector{}, false
		}
		observed.OperationID = "resendInvitationLink"
		observed.InvitationID = domain.EntityID(p[8])
	}
	return observed, true
}
