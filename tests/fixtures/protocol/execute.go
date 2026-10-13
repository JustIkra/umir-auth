package protocol

import (
	"context"
	"encoding/json"

	"github.com/JustIkra/umir-auth/bootstrap"
)

func (h *Handler) execute(ctx context.Context, r Request) Response {
	res := Response{Version: 1, Project: h.opts.Project, RequestID: r.RequestID, Operation: r.Operation}
	var in struct {
		ExpectedInstanceID string `json:"expectedInstanceID"`
		ExpectedGeneration string `json:"expectedGeneration"`
		Instant            string `json:"instant"`
	}
	if json.Unmarshal(r.Data, &in) != nil {
		return h.failure(r, "InvalidRequest")
	}
	switch r.Operation {
	case "fixture.ready":
		state := h.opts.Clock.Read()
		res.Data = ReadyState{Target: "auth", InstanceID: state.InstanceID, Protocol: Protocol, BinarySHA256: h.opts.BinarySHA256, ConfigSHA256: h.opts.ConfigSHA256, Ready: state.Healthy && h.opts.Ready(ctx), Capabilities: []string{"fixture.ready", "bootstrap.read", "clock.read", "clock.set", "clock.checkpoint", "owner.jobs", "owner.jobs.discover", "owner.fault.arm", "owner.fault.read", "owner.fault.clear"}}
	case "clock.read":
		res.Data = h.opts.Clock.Read()
	case "clock.set":
		if code := h.opts.Clock.Set(in.ExpectedInstanceID, in.ExpectedGeneration, in.Instant); code != "" {
			return h.failure(r, code)
		}
		res.Data = h.opts.Clock.Read()
	case "clock.checkpoint":
		state, ok := h.opts.Clock.ReadExpected(in.ExpectedInstanceID, in.ExpectedGeneration)
		if !ok {
			return h.failure(r, "ClockConflict")
		}
		b, e := json.Marshal(state)
		if e != nil {
			return h.failure(r, "ClockUnavailable")
		}
		var canonical any
		if json.Unmarshal(b, &canonical) != nil {
			return h.failure(r, "ClockUnavailable")
		}
		b, e = json.Marshal(canonical)
		if e != nil {
			return h.failure(r, "ClockUnavailable")
		}
		res.Data = struct {
			Clock ClockState `json:"clock"`
			SHA   string     `json:"checkpointSHA256"`
		}{state, SHA(b)}
	case "bootstrap.read":
		snapshot, e := h.opts.Store.Load(ctx)
		if e != nil {
			return h.failure(r, storeCode(e))
		}
		var user *bootstrap.InitialUser
		for _, u := range snapshot.Snapshot().Users {
			if u.UserID == h.opts.BootstrapID {
				profile := bootstrap.InitialUser{UserID: u.UserID, Login: u.Login, DisplayName: u.DisplayName, CredentialVersion: u.CredentialVersion, Email: u.Email}
				user = &profile
			}
		}
		if user == nil {
			return h.failure(r, "BootstrapConflict")
		}
		res.Data = struct {
			User        *bootstrap.InitialUser `json:"user"`
			Revision    string                 `json:"aggregateRevision"`
			Initialized bool                   `json:"initialized"`
			Binding     string                 `json:"profileBindingSHA256"`
		}{user, string(snapshot.Revision()), h.opts.Initialized, h.opts.BindingSHA256}
	case "owner.jobs.discover", "owner.jobs":
		data, code := h.jobs(ctx, r)
		if code != "" {
			return h.failure(r, code)
		}
		res.Data = data
	case "owner.fault.arm", "owner.fault.read", "owner.fault.clear":
		v, code := h.opts.Faults.Control(r.Operation, r.Data)
		if code != "" {
			return h.failure(r, code)
		}
		res.Data = v
	default:
		return h.failure(r, "UnsupportedOperation")
	}
	return res
}
