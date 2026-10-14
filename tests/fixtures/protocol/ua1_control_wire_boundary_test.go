package protocol

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestUA1ControlWireCacheCapacityCannotExecuteUnretainedArm(t *testing.T) {
	o, h, _ := ua1WireOwner(t)
	first := ua1WireRequest(t, o, "control.read", ua1ControlID(t), nil)
	original := ua1WireCall(t, h, first)
	if original.Code != 404 {
		t.Fatal(original.Code)
	}
	for i := 1; i < 256; i++ {
		request := ua1WireRequest(t, o, "control.read", first.ControlID, nil)
		if res := ua1WireCall(t, h, request); res.Code != 404 {
			input, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("cache rejection at %d: status=%d, response=%s, repeated validation=%v", i, res.Code, res.Body.String(), validateUA1ControlWire("Request", input))
		}
	}
	arm := ua1WireRequest(t, o, "control.arm", "", &UA1ControlArm{ControlID: ua1ControlID(t), Point: "before-process-mail", LifetimeMS: 100})
	if res := ua1WireCall(t, h, arm); res.Code != 413 {
		t.Fatal("new ID executed beyond retained capacity", res.Code)
	}
	o.controls.mu.Lock()
	n := len(o.controls.records)
	o.controls.mu.Unlock()
	if n != 0 {
		t.Fatal("unretained arm mutated controls")
	}
	if res := ua1WireCall(t, h, first); res.Code != original.Code || res.Body.String() != original.Body.String() {
		t.Fatal("cache eviction broke exact error replay")
	}
}

func TestUA1ControlWirePatternsStayStrictAndBounded(t *testing.T) {
	budget := &matchBudget{}
	budget.reset(schemaValidationLimit)
	r, err := compileUA1WirePattern(budget, `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if err != nil {
		t.Fatal(err)
	}
	valid := "44444444-4444-4444-8444-444444444444"
	for i := 0; i < 1024; i++ {
		if !r.MatchString(valid) {
			t.Fatal("valid bounded UUID refused")
		}
	}
	if r.MatchString(valid + "\n") {
		t.Fatal("trailing newline accepted")
	}
	if _, err = compileUA1WirePattern(budget, `(a+)+$`); err == nil {
		t.Fatal("unqualified pattern accepted")
	}
	budget.reset(schemaValidationLimit)
	budget.remaining = 0
	func() {
		defer func() {
			if _, ok := recover().(schemaMatchFailure); !ok {
				t.Fatal("match-work bound did not fail closed")
			}
		}()
		r.MatchString(valid)
	}()
}

func TestUA1ControlWireExpiredReleaseCannotAssertNoEffect(t *testing.T) {
	o, h, _ := ua1WireOwner(t)
	id := ua1ControlID(t)
	if res := ua1WireCall(t, h, ua1WireRequest(t, o, "control.arm", "", &UA1ControlArm{ControlID: id, Point: "before-process-mail", LifetimeMS: 100})); res.Code != 200 {
		t.Fatal(res.Code)
	}
	timer := time.NewTimer(110 * time.Millisecond)
	defer timer.Stop()
	<-timer.C
	req := ua1WireRequest(t, o, "control.release", id, nil)
	actual := ua1WireCall(t, h, req)
	var reply UA1ControlWireResponse
	if err := json.Unmarshal(actual.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if actual.Code != 409 || reply.Error == nil || reply.Error.Effect != "unknown" {
		t.Fatal("release after expiry asserted no effect", actual.Code, actual.Body.String())
	}
	if record := o.read(t, id); record.State != "expired" || record.EffectSequence == 0 {
		t.Fatal("actual expiry transition was lost")
	}
}

func TestUA1ControlWireClientRejectsForgedHitGeneration(t *testing.T) {
	o, h, _ := ua1WireOwner(t)
	id := ua1ControlID(t)
	if res := ua1WireCall(t, h, ua1WireRequest(t, o, "control.arm", "", &UA1ControlArm{ControlID: id, Point: "before-process-mail", LifetimeMS: 30000})); res.Code != 200 {
		t.Fatal(res.Code)
	}
	o.controls.mu.Lock()
	a := o.controls.records[id]
	err := o.controls.hit(context.Background(), a)
	o.controls.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	req := ua1WireRequest(t, o, "control.read", id, nil)
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	actual := ua1WireCall(t, h, req)
	var reply UA1ControlWireResponse
	if err = json.Unmarshal(actual.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	reply.Record.HitIdentity.ClockGeneration = "2"
	bad, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeUA1ControlWireResponse(body, bad, 200, req.Project); err == nil {
		t.Fatal("hit at another generation accepted")
	}
}

func TestUA1ControlWireClientRejectsCausalOrderCorruption(t *testing.T) {
	o, h, _ := ua1WireOwner(t)
	id := ua1ControlID(t)
	if res := ua1WireCall(t, h, ua1WireRequest(t, o, "control.arm", "", &UA1ControlArm{ControlID: id, Point: "before-process-mail", LifetimeMS: 30000})); res.Code != 200 {
		t.Fatal(res.Code)
	}
	o.controls.mu.Lock()
	a := o.controls.records[id]
	err := o.controls.hit(context.Background(), a)
	o.controls.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, code := o.controls.Release(context.Background(), UA1ControlBindingSHA256, o.identity(), id); code != "" {
		t.Fatal(code)
	}
	if err = o.controls.wait(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	req := ua1WireRequest(t, o, "control.read", id, nil)
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	actual := ua1WireCall(t, h, req)
	if _, err = DecodeUA1ControlWireResponse(body, actual.Body.Bytes(), actual.Code, req.Project); err != nil {
		t.Fatal("valid actual response refused", err)
	}
	var response UA1ControlWireResponse
	if err = json.Unmarshal(actual.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	response.Record.EffectSequence = response.Record.HitSequence
	corrupt, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeUA1ControlWireResponse(body, corrupt, 200, req.Project); err == nil {
		t.Fatal("effect before release was accepted")
	}
}
