package protocol

const UA1ControlWirePath = "/ua1-mail-controls/v1"
const UA1ControlWireSupplement = "umir-ua1-mail-control-wire/0.1.0-unpublished"
const UA1ControlWireBindingSHA256 = "5e546ae0c4db8d215d1f889bcdef413e50d4a5269351ceb49446a960f953eccd"

type UA1ControlWireRequest struct {
	Version       int            `json:"version"`
	Supplement    string         `json:"supplement"`
	BindingSHA256 string         `json:"bindingSHA256"`
	Project       string         `json:"project"`
	RequestID     string         `json:"requestID"`
	Owner         string         `json:"owner"`
	Expected      UA1Identity    `json:"expected"`
	Action        string         `json:"action"`
	ControlID     string         `json:"controlID,omitempty"`
	Arm           *UA1ControlArm `json:"arm,omitempty"`
}

type UA1ControlWireResponse struct {
	Version       int               `json:"version"`
	Supplement    string            `json:"supplement"`
	BindingSHA256 string            `json:"bindingSHA256"`
	Project       string            `json:"project"`
	RequestID     string            `json:"requestID"`
	Owner         string            `json:"owner"`
	Action        string            `json:"action"`
	Identity      *UA1Identity      `json:"identity,omitempty"`
	Record        *UA1ControlRecord `json:"record,omitempty"`
	Error         *Fault            `json:"error,omitempty"`
}
