package runtimehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/strictjson"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type Tokens interface {
	ServiceToken(context.Context, string, string, domain.EntityID, domain.EntityID, string) (application.IssuedToken, error)
}
type Peers struct {
	mu         sync.Mutex
	urls, keys map[string]string
	client     *http.Client
	tokens     Tokens
}

func New(urls, keys map[string]string, isolatedHTTP bool) (*Peers, error) {
	uCopy, kCopy := map[string]string{}, map[string]string{}
	for _, name := range []string{"warehouse", "serving", "gateway"} {
		u, e := url.Parse(urls[name])
		if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "https" && (!isolatedHTTP || u.Scheme != "http")) || len(keys[name]) != 64 {
			return nil, application.ErrAuthUnavailable
		}
		uCopy[name] = strings.TrimRight(urls[name], "/")
		kCopy[name] = keys[name]
	}
	return &Peers{urls: uCopy, keys: kCopy, client: &http.Client{Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 30 * time.Second}, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (p *Peers) Bind(tokens Tokens) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tokens != nil || tokens == nil {
		return application.ErrAuthUnavailable
	}
	p.tokens = tokens
	return nil
}
func (p *Peers) Status(ctx context.Context, name string) (application.RuntimeStatus, error) {
	var v application.RuntimeStatus
	e := p.call(ctx, name, "GET", "/internal/"+name+"/v2/runtime", nil, "", &v)
	return v, e
}
func (p *Peers) Register(ctx context.Context, name string, id domain.EntityID, in application.RegisterRuntime) (domain.PeerReadiness, error) {
	return p.mutate(ctx, name, id, in.ExpectedEpoch, "runtime.register", in)
}
func (p *Peers) Close(ctx context.Context, name string, id domain.EntityID, in application.CloseRuntime) (domain.PeerReadiness, error) {
	return p.mutate(ctx, name, id, in.ExpectedEpoch, "runtime.close", in)
}
func (p *Peers) mutate(ctx context.Context, name string, id, epoch domain.EntityID, operation string, in any) (domain.PeerReadiness, error) {
	p.mu.Lock()
	tokens := p.tokens
	p.mu.Unlock()
	if tokens == nil {
		return domain.PeerReadiness{}, application.ErrAuthUnavailable
	}
	token, e := tokens.ServiceToken(ctx, "auth", name, id, epoch, operation)
	if e != nil {
		return domain.PeerReadiness{}, e
	}
	method := "PUT"
	if operation == "runtime.close" {
		method = "DELETE"
	}
	var v domain.PeerReadiness
	e = p.call(ctx, name, method, "/internal/"+name+"/v2/r/"+url.PathEscape(string(id))+"/registry", in, token.Token, &v)
	return v, e
}
func (p *Peers) call(ctx context.Context, name, method, path string, in any, token string, out any) error {
	base, ok := p.urls[name]
	if !ok {
		return application.ErrAuthUnavailable
	}
	var body []byte
	var e error
	if in != nil {
		body, e = json.Marshal(in)
		if e != nil {
			return application.ErrAuthUnavailable
		}
	}
	r, e := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
	if e != nil {
		return application.ErrAuthUnavailable
	}
	r.Header.Set("X-Umir-Service-Key", p.keys[name])
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	res, e := p.client.Do(r)
	if e != nil {
		return application.ErrRuntimeNotReady
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, 1<<20+1))
	e = errors.Join(e, res.Body.Close())
	if e != nil || len(b) > 1<<20 || res.StatusCode != 200 || strictjson.CheckText(b) != nil {
		return application.ErrRuntimeNotReady
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(out); e != nil {
		return application.ErrRuntimeNotReady
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return application.ErrRuntimeNotReady
	}
	return nil
}

func (p *Peers) Shutdown() { p.client.CloseIdleConnections() }
