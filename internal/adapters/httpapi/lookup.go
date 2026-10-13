package httpapi

import (
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type storedWire struct {
	Type string `json:"type"`
	Body any    `json:"body,omitempty"`
}
type commandWire struct {
	State       string         `json:"state"`
	CommandID   string         `json:"commandID,omitempty"`
	OperationID string         `json:"operationID,omitempty"`
	HTTPStatus  int            `json:"httpStatus,omitempty"`
	Response    *storedWire    `json:"response,omitempty"`
	Revision    domain.Version `json:"aggregateRevision,omitempty"`
	Restore     *bool          `json:"requiresSessionRestore,omitempty"`
}

func lookupWire(v application.CommandResult) commandWire {
	wire := commandWire{State: v.State, CommandID: v.CommandID, OperationID: v.OperationID, HTTPStatus: v.HTTPStatus, Revision: v.Revision, Restore: v.Restore}
	if v.Response == nil {
		return wire
	}
	response := v.Response
	wire.Response = &storedWire{Type: response.Type}
	switch response.Type {
	case "UserView":
		if response.Session != nil {
			wire.Response.Body = wireView(*response.Session)
		}
	case "User":
		wire.Response.Body = response.User
	case "Organization":
		wire.Response.Body = response.Organization
	case "Membership":
		wire.Response.Body = response.Membership
	case "Invitation":
		wire.Response.Body = response.Invitation
	case "Challenge":
		wire.Response.Body = response.Challenge
	case "VerifiedChallenge":
		wire.Response.Body = response.Verified
	case "DurableResult":
		wire.Response.Body = response.Durable
	case "LifecycleResult":
		wire.Response.Body = response.Lifecycle
	}
	return wire
}
