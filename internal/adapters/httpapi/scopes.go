package httpapi

import (
	"net/http"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func bind[I, O any](h *handler, pattern string, status int, call func(*http.Request, I) (O, error)) {
	h.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if e := h.guard(r); e != nil {
			failure(w, e)
			return
		}
		var in I
		if e := decode(r, &in); e != nil {
			failure(w, e)
			return
		}
		v, e := call(r, in)
		respond(w, status, v, e)
	})
}

type command struct {
	CommandID string `json:"commandID"`
}

func session(r *http.Request) string                      { return r.Header.Get("X-Umir-Session") }
func csrf(r *http.Request) string                         { return r.Header.Get("X-Umir-CSRF-Token") }
func pathID(r *http.Request, name string) domain.EntityID { return domain.EntityID(r.PathValue(name)) }
func (h *handler) scopeRoutes() {
	bind(h, "POST /internal/auth/v1/public/orgs", 201, func(r *http.Request, in application.CreateOrganizationInput) (application.LifecycleResult, error) {
		return h.o.Accounts.CreateOrganization(r.Context(), session(r), csrf(r), in)
	})
	bind(h, "POST /internal/auth/v1/public/orgs/{orgID}/restaurants", 201, func(r *http.Request, in application.CreateRestaurantInput) (application.LifecycleResult, error) {
		return h.o.Accounts.CreateRestaurant(r.Context(), session(r), csrf(r), pathID(r, "orgID"), in)
	})
	bind(h, "DELETE /internal/auth/v1/public/orgs/{orgID}", 202, func(r *http.Request, in command) (application.LifecycleResult, error) {
		return h.o.Accounts.DeleteOrganization(r.Context(), session(r), csrf(r), pathID(r, "orgID"), in.CommandID)
	})
	bind(h, "DELETE /internal/auth/v1/public/orgs/{orgID}/restaurants/{restaurantID}", 202, func(r *http.Request, in command) (application.LifecycleResult, error) {
		return h.o.Accounts.DeleteRestaurant(r.Context(), session(r), csrf(r), pathID(r, "orgID"), pathID(r, "restaurantID"), in.CommandID)
	})
	h.mux.HandleFunc("GET /internal/auth/v1/public/orgs/{orgID}/lifecycle/{operationID}", func(w http.ResponseWriter, r *http.Request) {
		v, e := h.o.Accounts.Lifecycle(r.Context(), session(r), pathID(r, "orgID"), pathID(r, "operationID"))
		respond(w, 200, v, e)
	})
	bind(h, "PUT /internal/auth/v1/public/orgs/{orgID}/memberships/{membershipID}", 200, func(r *http.Request, in application.UpdateMembershipInput) (domain.Membership, error) {
		return h.o.Accounts.UpdateMembership(r.Context(), session(r), csrf(r), pathID(r, "orgID"), pathID(r, "membershipID"), in)
	})
	bind(h, "DELETE /internal/auth/v1/public/orgs/{orgID}/memberships/{membershipID}", 200, func(r *http.Request, in application.RevokeMembershipInput) (application.DurableResult, error) {
		return h.o.Accounts.RevokeMembership(r.Context(), session(r), csrf(r), pathID(r, "orgID"), pathID(r, "membershipID"), in)
	})
	bind(h, "DELETE /internal/auth/v1/public/orgs/{orgID}/memberships/{membershipID}/assignments/{assignmentID}", 200, func(r *http.Request, in application.RevokeAssignmentInput) (application.DurableResult, error) {
		return h.o.Accounts.RevokeAssignment(r.Context(), session(r), csrf(r), pathID(r, "orgID"), pathID(r, "membershipID"), pathID(r, "assignmentID"), in)
	})
}
func (h *handler) readRoutes() {
	h.mux.HandleFunc("GET /internal/auth/v1/public/access", func(w http.ResponseWriter, r *http.Request) {
		v, e := h.o.Accounts.Access(r.Context(), session(r))
		respond(w, 200, v, e)
	})
	h.mux.HandleFunc("GET /internal/auth/v1/public/orgs/{orgID}", func(w http.ResponseWriter, r *http.Request) {
		v, e := h.o.Accounts.Organization(r.Context(), session(r), pathID(r, "orgID"))
		respond(w, 200, v, e)
	})
	bind(h, "PATCH /internal/auth/v1/public/orgs/{orgID}/settings", 200, func(r *http.Request, in application.UpdateSettingsInput) (domain.Organization, error) {
		settings, e := h.o.Accounts.UpdateSettings(r.Context(), session(r), csrf(r), pathID(r, "orgID"), in)
		if e != nil {
			return domain.Organization{}, e
		}
		organization, e := h.o.Accounts.Organization(r.Context(), session(r), pathID(r, "orgID"))
		organization.Settings = settings
		return organization, e
	})
	h.mux.HandleFunc("POST /internal/auth/v1/readiness", func(w http.ResponseWriter, r *http.Request) {
		var in domain.PeerReadiness
		if e := decode(r, &in); e != nil {
			failure(w, e)
			return
		}
		caller, ok := r.Context().Value(callerKey{}).(string)
		if !ok {
			failure(w, application.ErrUnauthenticated)
			return
		}
		v, e := h.o.Accounts.Acknowledge(r.Context(), caller, in)
		respond(w, 200, v, e)
	})
}
func (h *handler) commandRoutes() {
	bind(h, "POST /internal/auth/v1/public/sessions/logout-all", 200, func(r *http.Request, in command) (application.DurableResult, error) {
		return h.o.Accounts.LogoutAllCommand(r.Context(), session(r), in.CommandID)
	})
	h.mux.HandleFunc("GET /internal/auth/v1/public/commands", func(w http.ResponseWriter, r *http.Request) {
		if session(r) == "" {
			if e := h.guard(r); e != nil {
				failure(w, e)
				return
			}
		}
		q := r.URL.Query()
		if len(q) != 2 || len(q["namespace"]) != 1 || len(q["commandID"]) != 1 {
			failure(w, application.ErrForbidden)
			return
		}
		v, e := h.o.Accounts.LookupCommand(r.Context(), h.actor(r), q.Get("namespace"), q.Get("commandID"))
		respond(w, 200, lookupWire(v), e)
	})
}
