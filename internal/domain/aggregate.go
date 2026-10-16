package domain

import "errors"

type EntityID string
type Version string
type Instant string

var ErrInvalidAggregate = errors.New("invalid auth aggregate")

type Aggregate struct {
	SchemaVersion     int                 `json:"schemaVersion"`
	AggregateRevision Version             `json:"aggregateRevision"`
	Users             []User              `json:"users"`
	Organizations     []Organization      `json:"organizations"`
	Restaurants       []Restaurant        `json:"restaurants"`
	Memberships       []Membership        `json:"memberships"`
	Sessions          []Session           `json:"sessions"`
	Invitations       []Invitation        `json:"invitations"`
	Challenges        []Challenge         `json:"challenges"`
	MailJobs          []MailJob           `json:"mailJobs"`
	Idempotency       []IdempotencyRecord `json:"idempotency"`
	LifecycleIntents  []LifecycleIntent   `json:"lifecycleIntents"`
	Tombstones        []Tombstone         `json:"tombstones"`
}
type User struct {
	UserID            EntityID `json:"userID"`
	Login             string   `json:"login"`
	DisplayName       string   `json:"displayName"`
	Email             string   `json:"email,omitempty"`
	CredentialVersion Version  `json:"credentialVersion"`
	Verifier          string   `json:"verifier"`
}
type Settings struct {
	TimeZone        string  `json:"timeZone"`
	SettingsVersion Version `json:"settingsVersion"`
}
type Organization struct {
	CreatedBy        EntityID `json:"createdBy,omitempty"`
	CreatedAt        Instant  `json:"createdAt,omitempty"`
	OrgID            EntityID `json:"orgID"`
	Name             string   `json:"name"`
	Settings         Settings `json:"settings"`
	Lifecycle        string   `json:"lifecycle"`
	LifecycleVersion Version  `json:"lifecycleVersion"`
}
type Restaurant struct {
	RestaurantID     EntityID `json:"restaurantID"`
	OrgID            EntityID `json:"orgID"`
	Name             string   `json:"name"`
	Lifecycle        string   `json:"lifecycle"`
	LifecycleVersion Version  `json:"lifecycleVersion"`
}
type Assignment struct {
	RestaurantID      EntityID `json:"restaurantID"`
	AssignmentID      EntityID `json:"assignmentID"`
	AssignmentVersion Version  `json:"assignmentVersion"`
	Roles             []string `json:"roles"`
}
type Membership struct {
	MembershipID      EntityID     `json:"membershipID"`
	MembershipVersion Version      `json:"membershipVersion"`
	UserID            EntityID     `json:"userID"`
	OrgID             EntityID     `json:"orgID"`
	OrgRoles          []string     `json:"orgRoles"`
	Assignments       []Assignment `json:"assignments"`
	State             string       `json:"state"`
}
type Session struct {
	SessionID         EntityID `json:"sessionID"`
	UserID            EntityID `json:"userID"`
	SessionVersion    Version  `json:"sessionVersion"`
	CredentialVersion Version  `json:"credentialVersion"`
	Digest            string   `json:"digest"`
	CSRFTokenDigest   string   `json:"csrfTokenDigest"`
	LegacyCSRF        bool     `json:"legacyCSRF,omitempty"`
	CreatedAt         Instant  `json:"createdAt"`
	IdleExpiresAt     Instant  `json:"idleExpiresAt"`
	AbsoluteExpiresAt Instant  `json:"absoluteExpiresAt"`
	RememberMe        bool     `json:"rememberMe"`
	Revoked           bool     `json:"revoked"`
}
type InviteAssignment struct {
	RestaurantID EntityID `json:"restaurantID"`
	Roles        []string `json:"roles"`
}
type Invitation struct {
	InvitationID      EntityID           `json:"invitationID"`
	OrgID             EntityID           `json:"orgID"`
	Email             string             `json:"email"`
	ComparisonEmail   string             `json:"comparisonEmail"`
	Assignments       []InviteAssignment `json:"assignments"`
	ExpiresAt         Instant            `json:"expiresAt"`
	ResendAvailableAt Instant            `json:"resendAvailableAt"`
	State             string             `json:"state"`
	Version           Version            `json:"version"`
}
type Challenge struct {
	SuppressedEmail        string    `json:"suppressedEmail,omitempty"`
	WrongAttemptTimes      []Instant `json:"wrongAttemptTimes,omitempty"`
	RegistrationEmail      string    `json:"registrationEmail,omitempty"`
	RegistrationSuppressed bool      `json:"registrationSuppressed,omitempty"`
	ChallengeID            EntityID  `json:"challengeID"`
	Purpose                string    `json:"purpose"`
	InvitationID           EntityID  `json:"invitationID,omitempty"`
	UserID                 EntityID  `json:"userID,omitempty"`
	CredentialVersion      Version   `json:"credentialVersion,omitempty"`
	InitiatorDigest        string    `json:"initiatorDigest"`
	CodeDigest             string    `json:"codeDigest"`
	EncryptedCode          string    `json:"encryptedCode"`
	ProofDigest            string    `json:"proofDigest,omitempty"`
	EncryptedProof         string    `json:"encryptedProof,omitempty"`
	ProofExpiresAt         Instant   `json:"proofExpiresAt,omitempty"`
	ExpiresAt              Instant   `json:"expiresAt"`
	ResendAvailableAt      Instant   `json:"resendAvailableAt"`
	State                  string    `json:"state"`
	IssueCount             int       `json:"issueCount"`
	WrongAttempts          int       `json:"wrongAttempts"`
}
type MailJob struct {
	Purpose          string   `json:"purpose,omitempty"`
	EnqueueOrder     Version  `json:"enqueueOrder,omitempty"`
	LeaseOwner       string   `json:"leaseOwner,omitempty"`
	LeaseUntil       Instant  `json:"leaseUntil,omitempty"`
	JobID            EntityID `json:"jobID"`
	ChallengeID      EntityID `json:"challengeID,omitempty"`
	OrgID            EntityID `json:"orgID,omitempty"`
	InvitationID     EntityID `json:"invitationID,omitempty"`
	State            string   `json:"state"`
	EncryptedPayload string   `json:"encryptedPayload"`
	AcceptedAt       Instant  `json:"acceptedAt"`
	Attempts         int      `json:"attempts"`
	LastAttemptAt    Instant  `json:"lastAttemptAt,omitempty"`
	NextAttemptAt    Instant  `json:"nextAttemptAt,omitempty"`
}
type IdempotencyRecord struct {
	ContractProfile   string     `json:"contractProfile,omitempty"`
	ActorID           EntityID   `json:"actorID,omitempty"`
	PreauthDigest     string     `json:"preauthDigest,omitempty"`
	OperationID       string     `json:"operationID"`
	OrgID             EntityID   `json:"orgID,omitempty"`
	RestaurantID      EntityID   `json:"restaurantID,omitempty"`
	CommandID         string     `json:"commandID"`
	Fingerprint       string     `json:"fingerprint"`
	AggregateRevision Version    `json:"aggregateRevision"`
	HTTPStatus        int        `json:"httpStatus"`
	ResponseSchema    string     `json:"responseSchema"`
	EncryptedResponse string     `json:"encryptedResponse"`
	JobIDs            []EntityID `json:"jobIDs"`
	RecordedAt        Instant    `json:"recordedAt,omitempty"`
}
type PeerReadiness struct {
	RestaurantID     EntityID `json:"restaurantID"`
	Service          string   `json:"service"`
	Epoch            EntityID `json:"epoch,omitempty"`
	State            string   `json:"state"`
	LifecycleVersion Version  `json:"lifecycleVersion"`
}
type LifecycleIntent struct {
	OperationID      EntityID        `json:"operationID"`
	CommandID        string          `json:"commandID"`
	ActorID          EntityID        `json:"actorID"`
	OrgID            EntityID        `json:"orgID"`
	RestaurantIDs    []EntityID      `json:"restaurantIDs"`
	Lifecycle        string          `json:"lifecycle"`
	LifecycleVersion Version         `json:"lifecycleVersion"`
	Cleanup          string          `json:"cleanup"`
	Services         []PeerReadiness `json:"services"`
}
type Tombstone struct {
	EntityID         EntityID `json:"entityID"`
	Kind             string   `json:"kind"`
	OrgID            EntityID `json:"orgID"`
	LifecycleVersion Version  `json:"lifecycleVersion"`
	DeletedAt        Instant  `json:"deletedAt"`
}
type ValidatedAggregate struct{ data Aggregate }

func Empty() Aggregate {
	return Aggregate{SchemaVersion: 1, AggregateRevision: "1", Users: []User{}, Organizations: []Organization{}, Restaurants: []Restaurant{}, Memberships: []Membership{}, Sessions: []Session{}, Invitations: []Invitation{}, Challenges: []Challenge{}, MailJobs: []MailJob{}, Idempotency: []IdempotencyRecord{}, LifecycleIntents: []LifecycleIntent{}, Tombstones: []Tombstone{}}
}
func (v ValidatedAggregate) Snapshot() Aggregate { return clone(v.data) }
func (v ValidatedAggregate) Revision() Version   { return v.data.AggregateRevision }

// Inspect calls fn with the stored aggregate itself, without the copy that
// Snapshot makes. fn must only read it and must not keep the pointer, or any
// slice or map reachable from it, after it returns: the storage and every other
// reader share that data.
func (v ValidatedAggregate) Inspect(fn func(*Aggregate)) { fn(&v.data) }
