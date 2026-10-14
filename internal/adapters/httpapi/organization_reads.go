package httpapi

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func organizationListRequest(w http.ResponseWriter, r *http.Request) (application.OrganizationListRequest, error) {
	in := application.OrganizationListRequest{}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1))
	if err != nil || len(body) != 0 || r.URL.RawPath != "" || !domain.ValidEntityID(pathID(r, "orgID")) || len(r.Header.Values("X-Umir-Session")) != 1 || len(r.Header.Values("X-Umir-Activity")) > 1 || r.URL.ForceQuery && r.URL.RawQuery == "" {
		return in, &application.FieldError{Field: "request", Code: "InvalidFormat"}
	}
	if activity := r.Header.Values("X-Umir-Activity"); len(activity) == 1 && activity[0] != "foreground" && activity[0] != "background" {
		return in, &application.FieldError{Field: "request", Code: "InvalidFormat"}
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return in, &application.FieldError{Field: "query", Code: "InvalidFormat"}
	}
	for key, items := range values {
		if key != "limit" && key != "cursor" && key != "state" || len(items) != 1 || items[0] == "" {
			return in, &application.FieldError{Field: "query", Code: "InvalidFormat"}
		}
	}
	if text, exists := values["limit"]; exists {
		in.Limit, err = strconv.Atoi(text[0])
		if err != nil || in.Limit < 1 || in.Limit > 500 || strconv.Itoa(in.Limit) != text[0] {
			return in, &application.FieldError{Field: "query", Code: "InvalidFormat"}
		}
	}
	in.Cursor, in.State = values.Get("cursor"), values.Get("state")
	return in, nil
}

func organizationReadFailure(w http.ResponseWriter, err error) {
	status, code := 503, "LimitExceeded"
	switch {
	case errors.Is(err, application.ErrRefreshRequired):
		status, code = 409, "RefreshRequired"
	case errors.Is(err, application.ErrLimitExceeded):
	case errors.Is(err, application.ErrScopeDeleted):
		status, code = 410, "ScopeDeleted"
	default:
		failure(w, err)
		return
	}
	type details struct {
		RefreshRequired bool `json:"refreshRequired"`
	}
	var metadata *details
	if code == "RefreshRequired" {
		metadata = &details{true}
	}
	write(w, status, struct {
		Code      string   `json:"code"`
		Outcome   string   `json:"outcome"`
		Message   string   `json:"message"`
		Retryable bool     `json:"retryable"`
		Details   *details `json:"details,omitempty"`
	}{code, "unavailable", "Collection could not be read", false, metadata})
}

func (h *handler) organizationReadRoutes() {
	for _, kind := range []string{"members", "invitations"} {
		h.mux.HandleFunc("GET /internal/auth/v1/public/orgs/{orgID}/"+kind, func(w http.ResponseWriter, r *http.Request) {
			in, err := organizationListRequest(w, r)
			if err != nil {
				organizationReadFailure(w, err)
				return
			}
			if strings.HasSuffix(r.URL.Path, "/members") {
				page, err := h.o.Accounts.Members(r.Context(), session(r), pathID(r, "orgID"), in)
				if err != nil {
					organizationReadFailure(w, err)
					return
				}
				write(w, 200, page)
			} else {
				page, err := h.o.Accounts.Invitations(r.Context(), session(r), pathID(r, "orgID"), in)
				if err != nil {
					organizationReadFailure(w, err)
					return
				}
				write(w, 200, page)
			}
		})
	}
}
