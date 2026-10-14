package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func DecodeUA1ControlWireResponse(request, body []byte, status int, project string) (UA1ControlWireResponse, error) {
	var input UA1ControlWireRequest
	var response UA1ControlWireResponse
	invalid := errors.New("invalid UA1 control wire response")
	if len(request) > MaxRequest || len(body) > MaxResponse || validateUA1ControlWire("Request", request) != nil || json.Unmarshal(request, &input) != nil || json.Unmarshal(body, &response) != nil {
		return response, invalid
	}
	name := "Response"
	if response.Error != nil {
		name = "Error"
	}
	if validateUA1ControlWire(name, body) != nil || response.BindingSHA256 != UA1ControlWireBindingSHA256 || response.Project != project || response.RequestID != input.RequestID || response.Action != input.Action {
		return response, invalid
	}
	if response.Error != nil {
		effect := "none"
		if response.Error.Code == "ObservationUnavailable" || response.Error.Code == "ControlConflict" {
			effect = "unknown"
		}
		if status != ua1ControlWireStatus(response.Error.Code) || response.Error.Effect != effect || response.Error.Retryable != (response.Error.Code == "WaitExpired" || response.Error.Code == "NotReady") {
			return response, invalid
		}
		return response, nil
	}
	if status != http.StatusOK || input.Project != project || input.BindingSHA256 != UA1ControlWireBindingSHA256 || response.Identity == nil || *response.Identity != input.Expected || response.Record == nil {
		return response, invalid
	}
	record := response.Record
	id := input.ControlID
	if input.Arm != nil {
		id = input.Arm.ControlID
		if record.Point != input.Arm.Point {
			return response, invalid
		}
	}
	if record.ControlID != id || record.Project != project || !sameUA1Instance(record.ArmIdentity, input.Expected) || record.Hits == 0 && (record.HitSequence != 0 || record.HitIdentity != nil) || record.Hits == 1 && (record.HitSequence <= record.ArmSequence || record.HitIdentity == nil) || record.ReleaseSequence == 0 && record.ReleaseIdentity != nil || record.ReleaseSequence != 0 && (record.ReleaseSequence <= record.HitSequence || record.ReleaseIdentity == nil) || record.EffectSequence == 0 && record.EffectIdentity != nil || record.EffectSequence != 0 && (record.EffectSequence <= record.ArmSequence || record.EffectIdentity == nil) {
		return response, invalid
	}
	for _, identity := range []*UA1Identity{record.HitIdentity, record.ReleaseIdentity, record.EffectIdentity} {
		if identity != nil && !sameUA1Instance(*identity, input.Expected) {
			return response, invalid
		}
	}
	if record.HitIdentity != nil && *record.HitIdentity != record.ArmIdentity {
		return response, invalid
	}
	if record.ReleaseSequence != 0 && record.Hits != 1 || record.EffectSequence != 0 && (record.EffectSequence <= record.HitSequence || record.EffectSequence <= record.ReleaseSequence) {
		return response, invalid
	}
	return response, nil
}

func CallUA1ControlWire(ctx context.Context, cfg Config, body []byte) ([]byte, int, error) {
	if len(body) > MaxRequest || validateUA1ControlWire("Request", body) != nil {
		return nil, 0, errors.New("invalid UA1 control wire request")
	}
	if err := CheckControlSocket(cfg.ControlSocket); err != nil {
		return nil, 0, err
	}
	credential, err := ReadCredential(cfg.ControlCredentialFile)
	if err != nil {
		return nil, 0, errors.New("control credential unavailable")
	}
	return callUA1ControlSocket(ctx, cfg.ControlSocket, credential, cfg.Project, body)
}

func callUA1ControlSocket(ctx context.Context, socket, credential, project string, body []byte) ([]byte, int, error) {
	if len(body) > MaxRequest || validateUA1ControlWire("Request", body) != nil || !digestPattern.MatchString(credential) {
		return nil, 0, errors.New("invalid UA1 control wire request")
	}
	if err := CheckControlSocket(socket); err != nil {
		return nil, 0, err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://fixture"+UA1ControlWirePath, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	r.Header.Set("Authorization", "Bearer "+credential)
	r.Header.Set("Content-Type", "application/json")
	res, err := client.Do(r)
	if err != nil {
		return nil, 0, errors.New("UA1 control unavailable")
	}
	data, readErr := io.ReadAll(io.LimitReader(res.Body, MaxResponse+1))
	closeErr := res.Body.Close()
	if readErr != nil || closeErr != nil || len(data) > MaxResponse || len(res.Header.Values("Content-Type")) != 1 || res.Header.Get("Content-Type") != "application/json" {
		return nil, 0, errors.New("UA1 control response unavailable")
	}
	if _, err = DecodeUA1ControlWireResponse(body, data, res.StatusCode, project); err != nil {
		return nil, 0, err
	}
	return data, res.StatusCode, nil
}

func UA1ControlFromStdin() error {
	cfg, _, err := LoadConfig(ConfigPath)
	if err != nil {
		return errors.New("invalid control configuration")
	}
	body, err := io.ReadAll(io.LimitReader(os.Stdin, MaxRequest+1))
	if err != nil || len(body) > MaxRequest {
		return errors.New("invalid control input")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	data, _, err := CallUA1ControlWire(ctx, cfg, body)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(data, '\n'))
	return err
}
