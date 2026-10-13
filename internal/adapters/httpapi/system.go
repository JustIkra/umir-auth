package httpapi

import (
	"net/http"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type tokenView struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
}

func (h *handler) systemRoutes() {
	h.mux.HandleFunc("POST /internal/auth/v1/anonymous-feedback-token", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Operation string `json:"operation"`
		}
		if e := decode(r, &in); e != nil || in.Operation != "feedback.anonymous.submit" {
			failure(w, application.ErrForbidden)
			return
		}
		v, e := h.o.Accounts.AnonymousToken(r.Context())
		respond(w, 200, tokenView{v.Token, v.ExpiresAt.Format("2006-01-02T15:04:05.999999999Z07:00")}, e)
	})
	h.mux.HandleFunc("POST /internal/auth/v1/service-tokens", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			RestaurantID domain.EntityID `json:"restaurantID"`
			Operation    string          `json:"operation"`
			Epoch        domain.EntityID `json:"epoch"`
		}
		if e := decode(r, &in); e != nil {
			failure(w, e)
			return
		}
		v, e := h.o.Accounts.ServiceToken(r.Context(), "gateway", "warehouse", in.RestaurantID, in.Epoch, in.Operation)
		respond(w, 200, tokenView{v.Token, v.ExpiresAt.Format("2006-01-02T15:04:05.999999999Z07:00")}, e)
	})
}
