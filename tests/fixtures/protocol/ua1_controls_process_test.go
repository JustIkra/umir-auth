package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/bootstrap"
	"github.com/JustIkra/umir-auth/internal/adapters/timezones"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type ua1CrashInput struct {
	StateFile  string                `json:"stateFile"`
	SecretsDir string                `json:"secretsDir"`
	HitFile    string                `json:"hitFile"`
	FixtureID  string                `json:"fixtureID"`
	InstanceID string                `json:"instanceID"`
	Instant    string                `json:"instant"`
	Initial    bootstrap.InitialUser `json:"initial"`
	Selector   UA1Selector           `json:"selector"`
}

func TestUA1ControlCrashOwnedProcessAndReopen(t *testing.T) {
	if inputPath := os.Getenv("UMIR_UA1_CRASH_INPUT"); inputPath != "" {
		ua1CrashChild(t, inputPath)
		return
	}
	o := newUA1ControlOwner(t)
	inv, job := o.create(t, "process-crash")
	if err := o.r.Close(); err != nil {
		t.Fatal(err)
	}
	instance := ua1ControlID(t)
	dir := filepath.Dir(o.opts.StateFile)
	in := ua1CrashInput{StateFile: o.opts.StateFile, SecretsDir: o.opts.SecretsDir, HitFile: filepath.Join(dir, "claim-hit.json"), FixtureID: o.clock.Read().FixtureID, InstanceID: instance, Instant: o.clock.Read().Instant, Initial: *o.opts.Initial, Selector: UA1Selector{Kind: "invitation_link", OrgID: o.org.OrgID, InvitationID: inv.InvitationID, JobID: job.JobID}}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(dir, "crash-input.json")
	if err = os.WriteFile(inputPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestUA1ControlCrashOwnedProcessAndReopen$", "-test.timeout=15s")
	cmd.Env = []string{"UMIR_UA1_CRASH_INPUT=" + inputPath, "PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "TMPDIR=" + os.Getenv("TMPDIR"), "GOMAXPROCS=2"}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			if err = cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Error(err)
			}
			if err = cmd.Wait(); err == nil {
				t.Error("child unexpectedly completed")
			}
		}
	}()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	var hit UA1ControlRecord
	for {
		data, err = os.ReadFile(in.HitFile)
		if err == nil {
			if bootstrap.DecodeStrict(data, &hit) != nil || hit.Hits != 1 || hit.State != "hit" || hit.HitIdentity == nil || hit.HitIdentity.InstanceID != instance || hit.Attempt != 1 {
				t.Fatal("child did not observe an actual claim")
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		select {
		case <-deadline.C:
			t.Fatal("owned child did not reach claim barrier")
		case <-tick.C:
		}
	}
	data, err = os.ReadFile(o.opts.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	var stored domain.Aggregate
	if bootstrap.DecodeStrict(data, &stored) != nil {
		t.Fatal("actual stored aggregate is malformed")
	}
	valid, err := domain.Validate(stored)
	if err != nil {
		t.Fatal("actual claimed aggregate is invalid")
	}
	if len(stored.MailJobs) != 1 || stored.MailJobs[0].JobID != job.JobID || stored.MailJobs[0].State != "sending" || stored.MailJobs[0].Attempts != 1 || valid.Revision() != hit.AggregateRevision {
		t.Fatal("hit does not join the durable JSON claim")
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	waited = true
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatal("owned process was not stopped", err)
	}
	reopenID := ua1ControlID(t)
	clock, err := NewClock(in.FixtureID, reopenID, in.Instant, "1")
	if err != nil {
		t.Fatal(err)
	}
	opts := o.opts
	opts.Clock = clock
	reopened, err := bootstrap.Open(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	})
	a, err := reopened.Store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	jobs := a.Snapshot().MailJobs
	if len(jobs) != 1 {
		t.Fatal("recovery changed job population")
	}
	recovered := jobs[0]
	if recovered.State != "unknown" || recovered.JobID != job.JobID || recovered.InvitationID != inv.InvitationID || recovered.Attempts != 1 || recovered.LastAttemptAt != domain.Instant(in.Instant) || recovered.NextAttemptAt != "2026-10-13T09:01:00+03:00" || recovered.EncryptedPayload != stored.MailJobs[0].EncryptedPayload || a.Revision() == valid.Revision() {
		t.Fatal("actual process recovery lost claim linkage")
	}
	if _, err = reopened.Accounts.ProcessMail(context.Background(), &ua1CountingSender{result: application.DeliveryResult{Success: true}}); err != nil {
		t.Fatal(err)
	}
	a, err = reopened.Store.Load(context.Background())
	if err != nil || a.Snapshot().MailJobs[0].Attempts != 1 {
		t.Fatal("recovery ignored the retained retry deadline")
	}
	state := clock.Read()
	if code := clock.Set(state.InstanceID, state.Generation, "2026-10-13T09:01:00+03:00"); code != "" {
		t.Fatal(code)
	}
	sender := &ua1CountingSender{result: application.DeliveryResult{Success: true}}
	if _, err = reopened.Accounts.ProcessMail(context.Background(), sender); err != nil {
		t.Fatal(err)
	}
	a, err = reopened.Store.Load(context.Background())
	if err != nil || len(a.Snapshot().MailJobs) != 1 || a.Snapshot().MailJobs[0].JobID != job.JobID || a.Snapshot().MailJobs[0].State != "delivered" || a.Snapshot().MailJobs[0].Attempts != 2 || sender.calls.Load() != 1 {
		t.Fatal("actual retry allocated another job")
	}
}

func ua1CrashChild(t *testing.T, inputPath string) {
	t.Helper()
	data, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	var in ua1CrashInput
	if bootstrap.DecodeStrict(data, &in) != nil {
		t.Fatal("invalid owned process input")
	}
	clock, err := NewClock(in.FixtureID, in.InstanceID, in.Instant, "1")
	if err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile("../../testdata/zoneinfo.zip")
	if err != nil {
		t.Fatal(err)
	}
	zones, err := timezones.New(data, "test")
	if err != nil {
		t.Fatal(err)
	}
	r, err := bootstrap.Open(context.Background(), bootstrap.Options{StateFile: in.StateFile, SecretsDir: in.SecretsDir, Initial: &in.Initial, Clock: clock, TimeZones: zones, Runtimes: localPeers{}, InvitationMail: application.InvitationMailOptions{FrontendOrigin: "https://app.umir.invalid"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	controls, err := NewUA1MailControls(HandlerOptions{Project: "umir-backend-000000000000000000000000", BinarySHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), Clock: clock, Store: r.Store}, r.AccountOptions.Results)
	if err != nil {
		t.Fatal(err)
	}
	defer controls.Close()
	id := ua1ControlID(t)
	expected := controls.identity()
	if _, code := controls.Arm(context.Background(), UA1ControlBindingSHA256, expected, UA1ControlArm{ControlID: id, Point: "after-durable-claim", LifetimeMS: 30000, Link: &in.Selector}); code != "" {
		t.Fatal(code)
	}
	done := make(chan error, 1)
	go func() {
		_, err := controls.ProcessMail(context.Background(), r.Accounts, &ua1CountingSender{result: application.DeliveryResult{Success: true}})
		done <- err
	}()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		record, code := controls.Read(context.Background(), UA1ControlBindingSHA256, expected, id)
		if code != "" {
			t.Fatal(code)
		}
		if record.State == "hit" {
			data, err = json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			tmp := in.HitFile + ".tmp"
			if err = os.WriteFile(tmp, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.Rename(tmp, in.HitFile); err != nil {
				t.Fatal(err)
			}
			break
		}
		select {
		case err = <-done:
			t.Fatal("worker ended before claim", err)
		case <-tick.C:
		}
	}
	if err = <-done; err != nil {
		t.Fatal("owned process was not stopped at claim", err)
	}
}
