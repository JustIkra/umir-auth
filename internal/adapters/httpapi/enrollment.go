package httpapi

import (
	"net/http"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func (h *handler) enrollmentRoutes() {
	bind(h, "POST /internal/auth/v1/public/orgs/{orgID}/invitations/{invitationID}/resend-link", 200, func(r *http.Request, in command) (application.DurableResult, error) {
		return h.o.Accounts.ResendInvitationLink(r.Context(), session(r), csrf(r), pathID(r, "orgID"), pathID(r, "invitationID"), in.CommandID)
	})
	bind(h, "POST /internal/auth/v1/public/orgs/{orgID}/invitations", 201, func(r *http.Request, in application.CreateInvitationInput) (domain.Invitation, error) {
		return h.o.Accounts.CreateInvitation(r.Context(), session(r), csrf(r), pathID(r, "orgID"), in)
	})
	bind(h, "POST /internal/auth/v1/public/orgs/{orgID}/invitations/{invitationID}/resend", 200, func(r *http.Request, in command) (application.DurableResult, error) {
		return h.o.Accounts.ResendInvitation(r.Context(), session(r), csrf(r), pathID(r, "orgID"), pathID(r, "invitationID"), in.CommandID)
	})
	bind(h, "DELETE /internal/auth/v1/public/orgs/{orgID}/invitations/{invitationID}", 200, func(r *http.Request, in command) (application.DurableResult, error) {
		return h.o.Accounts.CancelInvitation(r.Context(), session(r), csrf(r), pathID(r, "orgID"), pathID(r, "invitationID"), in.CommandID)
	})
	bind(h, "POST /internal/auth/v1/public/invitations/{invitationID}/challenges", 200, func(r *http.Request, in application.ChallengeBeginInput) (application.ChallengeView, error) {
		if in.InvitationID != pathID(r, "invitationID") {
			return application.ChallengeView{}, application.ErrForbidden
		}
		return h.o.Accounts.BeginInvitationChallenge(r.Context(), h.actor(r), application.ChallengeBeginInput{CommandID: in.CommandID, InvitationID: pathID(r, "invitationID")})
	})
	bind(h, "POST /internal/auth/v1/public/challenges/{challengeID}/resend", 200, func(r *http.Request, in command) (application.ChallengeView, error) {
		return h.o.Accounts.ResendChallenge(r.Context(), h.actor(r), pathID(r, "challengeID"), in.CommandID)
	})
	bind(h, "POST /internal/auth/v1/public/challenges/{challengeID}/verify", 200, func(r *http.Request, in application.ChallengeVerifyInput) (application.VerifiedChallenge, error) {
		if in.ChallengeID != pathID(r, "challengeID") {
			return application.VerifiedChallenge{}, application.ErrForbidden
		}
		return h.o.Accounts.VerifyChallenge(r.Context(), h.actor(r), application.ChallengeVerifyInput{CommandID: in.CommandID, ChallengeID: pathID(r, "challengeID"), Code: in.Code})
	})
	bind(h, "POST /internal/auth/v1/public/challenges/{challengeID}/complete", 200, func(r *http.Request, in application.InvitationCompleteInput) (sessionIssued, error) {
		if in.ChallengeID != pathID(r, "challengeID") {
			return sessionIssued{}, application.ErrForbidden
		}
		v, e := h.o.Accounts.CompleteInvitedUser(r.Context(), h.actor(r), application.InvitationCompleteInput{CommandID: in.CommandID, ChallengeID: pathID(r, "challengeID"), Proof: in.Proof, Password: in.Password, DisplayName: in.DisplayName})
		return wireSession(v), e
	})
	bind(h, "POST /internal/auth/v1/public/invitations/{invitationID}/accept", 200, func(r *http.Request, in application.InvitationAcceptInput) (domain.Membership, error) {
		return h.o.Accounts.AcceptInvitation(r.Context(), h.actor(r), pathID(r, "invitationID"), in)
	})
	bind(h, "POST /internal/auth/v1/public/email-challenges", 200, func(r *http.Request, in application.EmailChallengeInput) (application.ChallengeView, error) {
		return h.o.Accounts.BeginEmailChallenge(r.Context(), h.actor(r), in)
	})
	bind(h, "POST /internal/auth/v1/public/email-challenges/{challengeID}/complete", 200, func(r *http.Request, in application.EmailCompleteInput) (sessionIssued, error) {
		if in.ChallengeID != pathID(r, "challengeID") {
			return sessionIssued{}, application.ErrForbidden
		}
		v, e := h.o.Accounts.CompleteEmailChallenge(r.Context(), h.actor(r), application.EmailCompleteInput{CommandID: in.CommandID, ChallengeID: pathID(r, "challengeID"), Proof: in.Proof, Purpose: in.Purpose, RememberMe: in.RememberMe, NewPassword: in.NewPassword})
		return wireSession(v), e
	})
}
