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

func ProfileFromFile() error {
	cfg, _, e := LoadConfig(ConfigPath)
	if e != nil {
		return e
	}
	b, e := readFile(ProfileRequestPath, 65536, 0600)
	if e != nil {
		return e
	}
	if ValidateProfile("Request", b) != nil && ValidateProfile("CatalogRequest", b) != nil {
		return errors.New("invalid profile request")
	}
	if e = CheckControlSocket(cfg.ControlSocket); e != nil {
		return e
	}
	credential, e := ReadCredential(cfg.ControlCredentialFile)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", cfg.ControlSocket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, "POST", "http://fixture"+ProfilePath, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+credential)
	res, e := client.Do(req)
	if e != nil {
		return e
	}
	result, re := io.ReadAll(io.LimitReader(res.Body, MaxResponse+1))
	ce := res.Body.Close()
	if re != nil || ce != nil || len(result) > MaxResponse {
		return errors.Join(errors.New("profile bound"), re, ce)
	}
	schema := "Report"
	if ValidateProfile("CatalogRequest", b) == nil {
		schema = "CatalogReport"
	}
	if res.StatusCode != 200 {
		schema = "ProfileError"
	}
	if e = ValidateProfile(schema, result); e != nil {
		return e
	}
	var input, output struct {
		RequestID string `json:"requestID"`
	}
	if json.Unmarshal(b, &input) != nil || json.Unmarshal(result, &output) != nil || input.RequestID != output.RequestID {
		return errors.New("profile correlation")
	}
	_, e = os.Stdout.Write(append(result, '\n'))
	return e
}
