package profiles

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/jsonstore"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/tests/fixtures/protocol"
)

type childReport struct {
	Opened bool   `json:"opened"`
	Error  string `json:"error"`
}

func ProbeSecondWriter() (int, error) {
	pipe := os.NewFile(3, "profile-child-report")
	if pipe == nil {
		return 1, errors.New("missing child pipe")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	store, e := jsonstore.Open(ctx, statePath)
	report := childReport{Opened: e == nil}
	code := 1
	if errors.Is(e, application.ErrWriterLocked) {
		report.Error = "WriterLocked"
		code = 23
	} else if e == nil {
		e = store.Close()
	}
	b, me := json.Marshal(report)
	if me != nil {
		return 1, errors.Join(me, pipe.Close())
	}
	_, we := pipe.Write(b)
	ce := pipe.Close()
	if we != nil || ce != nil {
		return 1, errors.Join(we, ce)
	}
	if code != 23 {
		return code, errors.Join(errors.New("unexpected child admission"), e)
	}
	return code, nil
}
func secondWriter(ctx context.Context) (protocol.ProfileWriter, error) {
	exe, e := os.Executable()
	if e != nil {
		return protocol.ProfileWriter{}, e
	}
	reader, writer, e := os.Pipe()
	if e != nil {
		return protocol.ProfileWriter{}, e
	}
	childCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	child := exec.CommandContext(childCtx, exe, "probe-second-writer")
	child.ExtraFiles = []*os.File{writer}
	if e = child.Start(); e != nil {
		return protocol.ProfileWriter{}, errors.Join(e, reader.Close(), writer.Close())
	}
	if e = writer.Close(); e != nil {
		return protocol.ProfileWriter{}, errors.Join(e, child.Wait(), reader.Close())
	}
	b, re := io.ReadAll(io.LimitReader(reader, 4097))
	ce := reader.Close()
	wait := child.Wait()
	var exit *exec.ExitError
	if re != nil || ce != nil || len(b) > 4096 || !errors.As(wait, &exit) || exit.ExitCode() != 23 {
		return protocol.ProfileWriter{}, errors.Join(errors.New("child qualification failed"), re, ce, wait)
	}
	var report childReport
	if e = json.Unmarshal(b, &report); e != nil || report.Opened || report.Error != "WriterLocked" {
		return protocol.ProfileWriter{}, errors.New("invalid child report")
	}
	return protocol.ProfileWriter{Attempts: 1, PrimaryLockHeld: true, PrimaryReady: true, ChildOpened: false, ChildReady: false, ChildError: report.Error, Writers: 1, SameOwnedVolume: true, ChildExitCode: exit.ExitCode()}, nil
}
