package protocol

import "github.com/JustIkra/umir-auth/internal/domain"

const UA1Path = "/ua1-fixtures/v1"
const UA1Supplement = "umir-ua1-mail-fixtures/0.1.0-unpublished"
const UA1BindingSHA256 = "c468cb825a3b9bfe01577485f47267f4765c95286ac08de367002e3e25f3df45"

type UA1Identity struct {
	FixtureID       string `json:"fixtureID"`
	InstanceID      string `json:"instanceID"`
	ClockGeneration string `json:"clockGeneration"`
	BinarySHA256    string `json:"binarySHA256"`
	ConfigSHA256    string `json:"configSHA256"`
}

type UA1Selector struct {
	Kind         string          `json:"kind"`
	OrgID        domain.EntityID `json:"orgID,omitempty"`
	InvitationID domain.EntityID `json:"invitationID,omitempty"`
	ChallengeID  domain.EntityID `json:"challengeID,omitempty"`
	JobID        domain.EntityID `json:"jobID,omitempty"`
}

type UA1Request struct {
	Version       int         `json:"version"`
	Supplement    string      `json:"supplement"`
	BindingSHA256 string      `json:"bindingSHA256"`
	Project       string      `json:"project"`
	RequestID     string      `json:"requestID"`
	Owner         string      `json:"owner"`
	Expected      UA1Identity `json:"expected"`
	Action        string      `json:"action"`
	Selector      UA1Selector `json:"selector"`
}

type UA1CommandLink struct {
	OperationID       string          `json:"operationID"`
	CommandID         string          `json:"commandID"`
	ActorID           domain.EntityID `json:"actorID"`
	AggregateRevision domain.Version  `json:"aggregateRevision"`
}

type UA1Anchor struct {
	OrgID        domain.EntityID `json:"orgID,omitempty"`
	InvitationID domain.EntityID `json:"invitationID,omitempty"`
	ChallengeID  domain.EntityID `json:"challengeID,omitempty"`
}

type UA1Job struct {
	Kind          string          `json:"kind"`
	JobID         domain.EntityID `json:"jobID"`
	State         string          `json:"state"`
	Attempts      int             `json:"attempts"`
	AcceptedAt    domain.Instant  `json:"acceptedAt"`
	ExpiresAt     domain.Instant  `json:"expiresAt"`
	LastAttemptAt *domain.Instant `json:"lastAttemptAt"`
	NextAttemptAt *domain.Instant `json:"nextAttemptAt"`
	EnqueueOrder  *domain.Version `json:"enqueueOrder"`
	MessageID     string          `json:"messageID"`
	Anchor        UA1Anchor       `json:"anchor"`
	Command       *UA1CommandLink `json:"command,omitempty"`
}

type UA1Response struct {
	Version           int            `json:"version"`
	Supplement        string         `json:"supplement"`
	BindingSHA256     string         `json:"bindingSHA256"`
	Project           string         `json:"project"`
	RequestID         string         `json:"requestID"`
	Owner             string         `json:"owner"`
	Identity          UA1Identity    `json:"identity"`
	Instant           string         `json:"instant"`
	AggregateRevision domain.Version `json:"aggregateRevision"`
	Selector          UA1Selector    `json:"selector"`
	Jobs              []UA1Job       `json:"jobs"`
	Complete          bool           `json:"complete"`
}

type ua1Error struct {
	Version       int    `json:"version"`
	Supplement    string `json:"supplement"`
	BindingSHA256 string `json:"bindingSHA256"`
	Project       string `json:"project"`
	RequestID     string `json:"requestID"`
	Owner         string `json:"owner"`
	Error         Fault  `json:"error"`
}
