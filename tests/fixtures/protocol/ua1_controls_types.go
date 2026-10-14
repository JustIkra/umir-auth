package protocol

import "github.com/JustIkra/umir-auth/internal/domain"

const UA1ControlSupplement = "umir-ua1-mail-controls/0.1.0-unpublished"
const UA1ControlBindingSHA256 = "a89c877bc27aed78ac5c7ebee91a77c5a0680b8fbfb79fe7cc660e2f381d5738"

type UA1CommandDigest interface {
	Digest([]byte) (string, error)
}

type UA1CommandSelector struct {
	OperationID  string          `json:"operationID"`
	CommandID    string          `json:"commandID"`
	ActorID      domain.EntityID `json:"actorID"`
	OrgID        domain.EntityID `json:"orgID"`
	InvitationID domain.EntityID `json:"invitationID,omitempty"`
	BodySHA256   string          `json:"bodySHA256"`
}

type UA1ControlArm struct {
	ControlID  string              `json:"controlID"`
	Point      string              `json:"point"`
	LifetimeMS int                 `json:"lifetimeMs"`
	Command    *UA1CommandSelector `json:"command,omitempty"`
	Link       *UA1Selector        `json:"link,omitempty"`
}

type UA1ControlRecord struct {
	Version           int            `json:"version"`
	Supplement        string         `json:"supplement"`
	BindingSHA256     string         `json:"bindingSHA256"`
	Project           string         `json:"project"`
	Owner             string         `json:"owner"`
	ControlID         string         `json:"controlID"`
	Point             string         `json:"point"`
	State             string         `json:"state"`
	Reason            string         `json:"reason"`
	Hits              int            `json:"hits"`
	Effect            string         `json:"effect"`
	ArmIdentity       UA1Identity    `json:"armIdentity"`
	HitIdentity       *UA1Identity   `json:"hitIdentity"`
	ReleaseIdentity   *UA1Identity   `json:"releaseIdentity"`
	EffectIdentity    *UA1Identity   `json:"effectIdentity"`
	ArmSequence       uint64         `json:"armSequence"`
	HitSequence       uint64         `json:"hitSequence"`
	ReleaseSequence   uint64         `json:"releaseSequence"`
	EffectSequence    uint64         `json:"effectSequence"`
	AggregateRevision domain.Version `json:"aggregateRevision,omitempty"`
	Attempt           int            `json:"attempt"`
	Fingerprint       string         `json:"fingerprint,omitempty"`
	StoreOutcome      string         `json:"storeOutcome"`
	ReturnedOutcome   string         `json:"returnedOutcome"`
	SenderResult      string         `json:"senderResult"`
}
