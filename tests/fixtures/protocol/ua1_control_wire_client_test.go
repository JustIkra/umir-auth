package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUA1ControlWirePrivateUnixTransportAndMalformedReplies(t *testing.T) {
	o, h, _ := ua1WireOwner(t)
	root, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, "ua1-control-wire-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	if err = os.Chown(dir, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "auth.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(socket, 0600); err != nil {
		if ce := listener.Close(); ce != nil {
			t.Error(ce)
		}
		t.Fatal(err)
	}
	if err = os.Chown(socket, os.Getuid(), os.Getgid()); err != nil {
		if ce := listener.Close(); ce != nil {
			t.Error(ce)
		}
		t.Fatal(err)
	}
	server := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
	})
	req := ua1WireRequest(t, o, "control.arm", "", &UA1ControlArm{ControlID: ua1ControlID(t), Point: "before-process-mail", LifetimeMS: 30000})
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	data, status, err := callUA1ControlSocket(context.Background(), socket, strings.Repeat("a", 64), req.Project, body)
	if err != nil || status != 200 {
		t.Fatal("private Unix transport failed", status, err)
	}
	var original UA1ControlWireResponse
	if err = json.Unmarshal(data, &original); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*UA1ControlWireResponse){
		func(r *UA1ControlWireResponse) { r.Project = "umir-backend-111111111111111111111111" },
		func(r *UA1ControlWireResponse) { r.RequestID = ua1ControlID(t) },
		func(r *UA1ControlWireResponse) { r.BindingSHA256 = strings.Repeat("d", 64) },
		func(r *UA1ControlWireResponse) { r.Record.ControlID = ua1ControlID(t) },
		func(r *UA1ControlWireResponse) { r.Identity.ClockGeneration = "2" },
	} {
		var changed UA1ControlWireResponse
		if err = json.Unmarshal(data, &changed); err != nil {
			t.Fatal(err)
		}
		mutate(&changed)
		bad, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = DecodeUA1ControlWireResponse(body, bad, 200, req.Project); err == nil {
			t.Fatal("corrupt response accepted")
		}
	}
	if _, err = DecodeUA1ControlWireResponse(body, data[:len(data)-1], 200, req.Project); err == nil {
		t.Fatal("truncated response accepted")
	}
	if _, err = DecodeUA1ControlWireResponse(body, data, 503, req.Project); err == nil {
		t.Fatal("status mismatch accepted")
	}
	if err = os.Chmod(socket, 0660); err != nil {
		t.Fatal(err)
	}
	if _, _, err = callUA1ControlSocket(context.Background(), socket, strings.Repeat("a", 64), req.Project, body); err == nil {
		t.Fatal("unsafe socket accepted")
	}
}
