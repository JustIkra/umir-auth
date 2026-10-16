package httpapi

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/JustIkra/umir-auth/internal/adapters/jwt"
	"github.com/JustIkra/umir-auth/internal/adapters/strictjson"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type Options struct {
	Accounts    *application.Accounts
	Signer      *jwt.Signer
	Clock       application.Clock
	Preauth     *Preauth
	ServiceKeys map[string]string
	Ready       func(context.Context) error
	// JWKSReady, when set, replaces Ready for the key-set route: publishing the
	// keys depends on the signing key only.
	JWKSReady func(context.Context) error
}
type handler struct {
	o   Options
	mux *http.ServeMux
}

var keyPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func New(o Options) (http.Handler, error) {
	if o.Accounts == nil || o.Signer == nil || o.Clock == nil || o.Preauth == nil {
		return nil, application.ErrAuthUnavailable
	}
	keys := map[string]string{}
	seen := map[string]bool{}
	for name, k := range o.ServiceKeys {
		if name != "gateway" && name != "serving" && name != "warehouse" && name != "feedback" {
			return nil, application.ErrAuthUnavailable
		}
		if !keyPattern.MatchString(k) || seen[k] {
			return nil, application.ErrAuthUnavailable
		}
		keys[name] = k
		seen[k] = true
	}
	if keys["gateway"] == "" || keys["serving"] == "" {
		return nil, application.ErrAuthUnavailable
	}
	o.ServiceKeys = keys
	h := &handler{o: o, mux: http.NewServeMux()}
	h.routes()
	return h, nil
}
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	for name, key := range h.o.ServiceKeys {
		if name == "feedback" {
			for _, supplied := range r.Header.Values("X-Umir-Service-Key") {
				if subtle.ConstantTimeCompare([]byte(supplied), []byte(key)) == 1 && (r.Method != "GET" || r.URL.Path != "/internal/auth/v1/jwks" || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery) {
					failure(w, application.ErrForbidden)
					return
				}
			}
		}
	}
	if r.URL.Path == "/healthz" {
		write(w, 200, struct {
			Status string `json:"status"`
		}{"ok"})
		return
	}
	if len(r.Header.Values("X-Umir-Service-Key")) != 1 {
		failure(w, application.ErrUnauthenticated)
		return
	}
	caller := ""
	for name, key := range h.o.ServiceKeys {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Umir-Service-Key")), []byte(key)) == 1 {
			caller = name
		}
	}
	if caller == "" {
		failure(w, application.ErrUnauthenticated)
		return
	}
	if caller != "gateway" && r.URL.Path != "/internal/auth/v1/jwks" && r.URL.Path != "/internal/auth/v1/registry" && r.URL.Path != "/internal/auth/v1/readiness" {
		failure(w, application.ErrForbidden)
		return
	}
	ready := h.o.Ready
	if h.o.JWKSReady != nil && r.URL.Path == "/internal/auth/v1/jwks" {
		ready = h.o.JWKSReady
	}
	if ready != nil {
		if e := ready(r.Context()); e != nil {
			failure(w, application.ErrAuthUnavailable)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	h.mux.ServeHTTP(w, r.WithContext(context.WithValue(ctx, callerKey{}, caller)))
}

type callerKey struct{}

func write(w http.ResponseWriter, status int, v any) {
	b, e := json.Marshal(v)
	if e != nil {
		failure(w, application.ErrAuthUnavailable)
		return
	}
	w.WriteHeader(status)
	if _, e = w.Write(b); e != nil {
		return
	}
}
func decode(r *http.Request, v any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return &application.FieldError{Field: "request", Code: "InvalidFormat"}
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if e != nil || len(b) > 1<<20 || !utf8.Valid(b) || strictjson.CheckText(b) != nil {
		return &application.FieldError{Field: "request", Code: "InvalidFormat"}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if e = walkJSON(d, 0); e != nil {
		return &application.FieldError{Field: "request", Code: "InvalidFormat"}
	}
	if _, e = d.Token(); !errors.Is(e, io.EOF) {
		return &application.FieldError{Field: "request", Code: "InvalidFormat"}
	}
	if e = schemaCheck(r, b); e != nil {
		return &application.FieldError{Field: "request", Code: "InvalidFormat"}
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(v); e != nil {
		return &application.FieldError{Field: "request", Code: "InvalidFormat"}
	}
	return nil
}
func walkJSON(d *json.Decoder, depth int) error {
	if depth > 16 {
		return application.ErrForbidden
	}
	t, e := d.Token()
	if e != nil {
		return e
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := k.(string)
			if !ok || seen[s] {
				return application.ErrForbidden
			}
			seen[s] = true
			if e = walkJSON(d, depth+1); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e = walkJSON(d, depth+1); e != nil {
				return e
			}
		}
	default:
		return application.ErrForbidden
	}
	_, e = d.Token()
	return e
}
func failure(w http.ResponseWriter, e error) {
	status, code, outcome := 503, "AuthUnavailable", "unavailable"
	switch {
	case errors.Is(e, application.ErrUnauthenticated):
		status, code, outcome = 401, "Unauthenticated", "not_committed"
	case errors.Is(e, application.ErrInvalidCredentials):
		status, code, outcome = 401, "InvalidCredentials", "not_committed"
	case errors.Is(e, application.ErrInvalidCSRFToken):
		status, code, outcome = 403, "InvalidCsrfToken", "not_committed"
	case errors.Is(e, application.ErrForbidden):
		status, code, outcome = 403, "Forbidden", "not_committed"
	case errors.Is(e, application.ErrCommandResultCleared):
		status, code, outcome = 409, "CommandConflict", "unknown"
	case errors.Is(e, application.ErrCommandConflict):
		status, code, outcome = 409, "CommandConflict", "not_committed"
	case errors.Is(e, application.ErrRuntimeNotReady):
		status, code, outcome = 503, "RuntimeNotReady", "unavailable"
	case errors.Is(e, application.ErrScopeDeleted):
		status, code, outcome = 409, "ScopeDeleted", "not_committed"
	case errors.Is(e, application.ErrLastAdmin):
		status, code, outcome = 409, "LastAdmin", "not_committed"
	case errors.Is(e, application.ErrMembershipConflict):
		status, code, outcome = 409, "CommandConflict", "not_committed"
	case errors.Is(e, application.ErrSettingsChanged):
		status, code, outcome = 409, "SettingsChanged", "not_committed"
	case errors.Is(e, application.ErrUnknownTimeZone):
		status, code, outcome = 422, "UnknownTimeZone", "not_committed"
	case errors.Is(e, application.ErrTimeZoneDataUnavailable):
		code, outcome = "TimeZoneDataUnavailable", "unavailable"
	case errors.Is(e, application.ErrCurrentPasswordIncorrect):
		status, code, outcome = 400, "CurrentPasswordIncorrect", "not_committed"
	case errors.Is(e, application.ErrLoginRateLimited):
		status, code, outcome = 429, "LoginRateLimited", "not_committed"
	case errors.Is(e, application.ErrPasswordChangeRateLimited):
		status, code, outcome = 429, "PasswordChangeRateLimited", "not_committed"
	case errors.Is(e, application.ErrChallengeRateLimited):
		status, code, outcome = 429, "RateLimited", "not_committed"
	case errors.Is(e, application.ErrDeliveryUnavailable):
		status, code, outcome = 503, "DeliveryUnavailable", "not_committed"
	case errors.Is(e, application.ErrChallengeLocked):
		status, code, outcome = 400, "ChallengeLocked", "not_committed"
	case errors.Is(e, application.ErrChallengeInvalidCode):
		status, code, outcome = 400, "InvalidArgument", "committed"
	case errors.Is(e, application.ErrInvitationUnavailable), errors.Is(e, application.ErrChallengeUnavailable):
		status, code, outcome = 404, "NotFound", "unavailable"
	case errors.Is(e, application.ErrInvitationConflict):
		status, code, outcome = 409, "CommandConflict", "not_committed"
	case errors.Is(e, application.ErrUpdateOutcomeUnknown):
		code, outcome = "AuthUpdateOutcomeUnknown", "unknown"
	case errors.Is(e, application.ErrStorageUnavailable):
		code, outcome = "AuthStorageUnavailable", "not_committed"
	default:
		var f *application.FieldError
		if errors.As(e, &f) {
			status, code, outcome = 400, "InvalidArgument", "not_committed"
		}
	}
	result := struct {
		Code           string        `json:"code"`
		Outcome        string        `json:"outcome"`
		Message        string        `json:"message"`
		Retryable      bool          `json:"retryable"`
		SessionRevoked *bool         `json:"sessionRevoked,omitempty"`
		Details        *retryDetails `json:"details,omitempty"`
	}{Code: code, Outcome: outcome, Message: "Request could not be completed"}
	var passwordLimit *application.PasswordChangeLimitError
	var loginLimit *application.RateLimitError
	var invitationLimit *application.InvitationRateLimitError
	var delay time.Duration
	if errors.As(e, &passwordLimit) {
		result.SessionRevoked = &passwordLimit.SessionRevoked
		delay = passwordLimit.RetryAfter
	} else if errors.As(e, &loginLimit) {
		delay = loginLimit.RetryAfter
	} else if errors.As(e, &invitationLimit) {
		delay = invitationLimit.RetryAfter
	}
	if delay > 0 {
		seconds := int((delay-1)/time.Second) + 1
		result.Details = &retryDetails{seconds}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
	}
	write(w, status, result)
}

type retryDetails struct {
	RetryAfterSeconds int `json:"retryAfterSeconds"`
}

func respond[T any](w http.ResponseWriter, status int, v T, e error) {
	if e != nil {
		failure(w, e)
		return
	}
	if status == 204 {
		w.WriteHeader(status)
		return
	}
	if lifecycle, ok := any(v).(application.LifecycleResult); ok {
		peers := []domain.PeerReadiness{}
		for _, p := range lifecycle.Services {
			if p.Epoch != "" {
				peers = append(peers, p)
			}
		}
		lifecycle.Services = peers
		write(w, status, lifecycle)
		return
	}
	write(w, status, v)
}
func (h *handler) guard(r *http.Request) error {
	token, csrf := r.Header.Get("X-Umir-Session"), r.Header.Get("X-Umir-CSRF-Token")
	if token != "" {
		_, e := h.o.Accounts.Authorize(r.Context(), token, csrf, false)
		return e
	}
	return h.o.Preauth.Verify(r.Header.Get("X-Umir-Preauth"), csrf)
}
func (h *handler) actor(r *http.Request) application.ChallengeActor {
	a := application.ChallengeActor{Token: r.Header.Get("X-Umir-Session"), CSRFToken: r.Header.Get("X-Umir-CSRF-Token")}
	if a.Token == "" {
		a.PreauthDigest = application.TokenDigest(r.Header.Get("X-Umir-Preauth"))
	}
	return a
}

type userView struct {
	User    application.UserView         `json:"user"`
	Session application.SessionDeadlines `json:"session"`
}
type sessionIssued struct {
	View         userView `json:"view"`
	SessionToken string   `json:"sessionToken"`
}

func wireView(v application.SessionView) userView {
	return userView{v.User, application.SessionDeadlines{ExpiresAt: v.Session.IdleExpiresAt, IdleExpiresAt: v.Session.IdleExpiresAt, AbsoluteExpiresAt: v.Session.AbsoluteExpiresAt, RememberMe: v.Session.RememberMe, CSRFToken: v.CSRFToken}}
}
func wireSession(v application.SessionView) sessionIssued { return sessionIssued{wireView(v), v.Token} }
func (h *handler) routes() {
	h.mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if h.o.Ready != nil {
			if e := h.o.Ready(r.Context()); e != nil {
				failure(w, e)
				return
			}
		}
		write(w, 200, struct {
			Ready bool `json:"ready"`
		}{true})
	})
	h.mux.HandleFunc("GET /internal/auth/v1/jwks", func(w http.ResponseWriter, r *http.Request) {
		v, e := h.o.Signer.JWKS(r.Context())
		respond(w, 200, v, e)
	})
	h.mux.HandleFunc("GET /internal/auth/v1/registry", func(w http.ResponseWriter, r *http.Request) {
		v, e := h.o.Accounts.Registry(r.Context())
		respond(w, 200, v, e)
	})
	h.mux.HandleFunc("POST /internal/auth/v1/authorize", func(w http.ResponseWriter, r *http.Request) {
		var in application.AuthorizationInput
		if e := decode(r, &in); e != nil {
			failure(w, e)
			return
		}
		v, e := h.o.Accounts.AuthorizeToken(r.Context(), in)
		respond(w, 200, v, e)
	})
	h.mux.HandleFunc("POST /internal/auth/v1/access-check", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			SessionToken string          `json:"sessionToken"`
			RestaurantID domain.EntityID `json:"restaurantID"`
			Operation    string          `json:"operation"`
		}
		if e := decode(r, &in); e != nil {
			failure(w, e)
			return
		}
		p, ok := application.UserTokenPolicy(in.Operation)
		if !ok && in.Operation != "live" {
			failure(w, application.ErrForbidden)
			return
		}
		v, e := h.o.Accounts.RestaurantAccess(r.Context(), in.SessionToken, in.RestaurantID)
		if e == nil {
			found := in.Operation == "live"
			for _, c := range v.Permissions {
				found = found || c == p.Capability
			}
			if !found {
				e = application.ErrForbidden
			}
		}
		respond(w, 200, v, e)
	})
	h.mux.HandleFunc("GET /internal/auth/v1/public/csrf", func(w http.ResponseWriter, r *http.Request) {
		if token := r.Header.Get("X-Umir-Session"); token != "" {
			v, e := h.o.Accounts.SessionCSRF(r.Context(), token)
			respond(w, 200, struct {
				Token string `json:"csrfToken"`
			}{v}, e)
			return
		}
		v, e := h.o.Preauth.Issue(r.Header.Get("X-Umir-Preauth"))
		respond(w, 200, v, e)
	})
	h.mux.HandleFunc("POST /internal/auth/v1/public/session", func(w http.ResponseWriter, r *http.Request) {
		if e := h.guard(r); e != nil {
			failure(w, e)
			return
		}
		var in struct {
			Login      string `json:"login"`
			Password   string `json:"password"`
			RememberMe bool   `json:"rememberMe"`
			CommandID  string `json:"commandID"`
		}
		if e := decode(r, &in); e != nil || in.CommandID == "" {
			failure(w, &application.FieldError{Field: "commandID", Code: "Required"})
			return
		}
		v, e := h.o.Accounts.Login(r.Context(), application.LoginInput{Login: in.Login, Password: in.Password, RememberMe: in.RememberMe, CommandID: in.CommandID, PreviousToken: r.Header.Get("X-Umir-Session"), PreauthDigest: application.TokenDigest(r.Header.Get("X-Umir-Preauth"))})
		respond(w, 200, wireSession(v), e)
	})
	h.mux.HandleFunc("GET /internal/auth/v1/public/me", func(w http.ResponseWriter, r *http.Request) {
		var v application.SessionView
		var e error
		if r.Header.Get("X-Umir-Activity") == "background" {
			v, e = h.o.Accounts.Peek(r.Context(), r.Header.Get("X-Umir-Session"))
		} else {
			v, e = h.o.Accounts.Current(r.Context(), r.Header.Get("X-Umir-Session"))
		}
		respond(w, 200, wireView(v), e)
	})
	h.mux.HandleFunc("DELETE /internal/auth/v1/public/session", func(w http.ResponseWriter, r *http.Request) {
		if e := h.guard(r); e != nil {
			failure(w, e)
			return
		}
		e := h.o.Accounts.Logout(r.Context(), r.Header.Get("X-Umir-Session"))
		respond(w, 204, struct{}{}, e)
	})
	h.mux.HandleFunc("PATCH /internal/auth/v1/public/me/display-name", func(w http.ResponseWriter, r *http.Request) {
		if e := h.guard(r); e != nil {
			failure(w, e)
			return
		}
		var in struct {
			DisplayName string `json:"displayName"`
			CommandID   string `json:"commandID"`
		}
		if e := decode(r, &in); e != nil {
			failure(w, e)
			return
		}
		v, e := h.o.Accounts.UpdateDisplayNameCommand(r.Context(), r.Header.Get("X-Umir-Session"), in.DisplayName, in.CommandID)
		respond(w, 200, v, e)
	})
	h.mux.HandleFunc("PATCH /internal/auth/v1/public/me/password", func(w http.ResponseWriter, r *http.Request) {
		if e := h.guard(r); e != nil {
			failure(w, e)
			return
		}
		var in struct {
			CurrentPassword string `json:"currentPassword"`
			NewPassword     string `json:"newPassword"`
			CommandID       string `json:"commandID"`
		}
		if e := decode(r, &in); e != nil {
			failure(w, e)
			return
		}
		e := h.o.Accounts.ChangePasswordCommand(r.Context(), r.Header.Get("X-Umir-Session"), in.CurrentPassword, in.NewPassword, in.CommandID)
		respond(w, 204, struct{}{}, e)
	})
	h.scopeRoutes()
	h.enrollmentRoutes()
	h.systemRoutes()
	h.readRoutes()
	h.commandRoutes()
	h.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		write(w, 404, struct {
			Code      string `json:"code"`
			Outcome   string `json:"outcome"`
			Message   string `json:"message"`
			Retryable bool   `json:"retryable"`
		}{"NotFound", "not_committed", "Route not found", false})
	})
}
