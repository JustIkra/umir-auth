package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"

	"syscall"
	"time"

	"github.com/JustIkra/umir-auth/bootstrap"
	mail "github.com/JustIkra/umir-auth/internal/adapters/mail"
	"github.com/JustIkra/umir-auth/internal/adapters/runtimehttp"
	"github.com/JustIkra/umir-auth/internal/adapters/timezones"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/tests/fixtures/protocol"
	"github.com/JustIkra/umir-auth/tests/mailobserver"
)

func main() {
	var e error
	if len(os.Args) != 2 {
		e = errors.New("command required")
	} else {
		switch os.Args[1] {
		case "serve":
			e = serve()
		case "healthcheck":
			e = protocol.Healthcheck()
		default:
			e = errors.New("unsupported command")
		}
	}
	if e != nil {
		if _, e = fmt.Fprintln(os.Stderr, "Auth fixture unavailable"); e != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}
}
func serve() error {
	cfg, digest, e := protocol.LoadConfig(protocol.ConfigPath)
	if e != nil {
		return e
	}
	credential, e := protocol.ReadCredential(cfg.ControlCredentialFile)
	if e != nil {
		return e
	}
	keys := map[string]string{}
	seen := map[string]bool{credential: true}
	for name, ref := range cfg.CredentialFiles {
		key, e := protocol.ReadCredential(ref)
		if e != nil || seen[key] {
			return errors.New("invalid fixture key")
		}
		seen[key] = true
		keys[name] = key
	}
	var initial struct {
		User         bootstrap.InitialUser `json:"user"`
		PasswordFile protocol.FileRef      `json:"passwordFile"`
		StateFile    string                `json:"stateFile"`
		Mode         string                `json:"mode"`
	}
	if bootstrap.DecodeStrict(cfg.Bootstrap, &initial) != nil || initial.PasswordFile != (protocol.FileRef{Target: "auth", Path: "/run/umir-fixtures/secrets/bootstrap-password"}) || initial.StateFile != cfg.StateFile || initial.Mode != "initialize-if-absent-validate-if-present" || initial.User != (bootstrap.InitialUser{UserID: "11111111-1111-4111-8111-111111111111", Login: "e2e.initial", DisplayName: "E2E Initial Operator", CredentialVersion: "1"}) {
		return errors.New("invalid bootstrap binding")
	}
	password, e := bootstrap.ReadPrivateFile(initial.PasswordFile.Path, 32)
	if e != nil || len(password) != 32 {
		return errors.New("invalid bootstrap password")
	}
	defer clear(password)
	for _, b := range password {
		if b < '0' || b > '9' && b < 'a' || b > 'f' {
			return errors.New("invalid bootstrap password")
		}
	}
	instance, e := protocol.UUID()
	if e != nil {
		return e
	}
	clock, e := protocol.NewClock(cfg.FixtureID, instance, cfg.InitialInstant, cfg.ClockGeneration)
	if e != nil {
		return e
	}
	zones, e := packagedZones()
	if e != nil {
		return e
	}
	peers, e := runtimehttp.New(map[string]string{"warehouse": cfg.ServiceURLs["warehouse"], "serving": cfg.ServiceURLs["serving"], "gateway": cfg.ServiceURLs["gateway"]}, map[string]string{"warehouse": keys["auth-warehouse"], "serving": keys["auth-serving"], "gateway": keys["auth-gateway"]}, true)
	if e != nil {
		return e
	}
	defer peers.Shutdown()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	runtime, e := bootstrap.Open(ctx, bootstrap.Options{StateFile: cfg.StateFile, SecretsDir: filepath.Join(filepath.Dir(cfg.StateFile), "secrets"), Initial: &initial.User, Password: string(password), Clock: clock, TimeZones: zones, Runtimes: peers})
	if e != nil {
		return e
	}
	defer func() {
		if ce := runtime.Close(); ce != nil {
			stop()
		}
	}()
	faults := &protocol.Faults{}
	options := runtime.AccountOptions
	options.Repository = &protocol.FaultRepository{Store: runtime.Store, Faults: faults}
	runtime.Accounts, e = application.NewAccounts(ctx, options)
	if e != nil {
		return e
	}
	if e = peers.Bind(runtime.Accounts); e != nil {
		return e
	}
	handler, e := runtime.Handler(map[string]string{"gateway": keys["gateway-auth"], "serving": keys["serving-auth"], "warehouse": keys["auth-warehouse"]})
	if e != nil {
		return e
	}
	binary, e := protocol.BinarySHA()
	if e != nil {
		return e
	}
	control, e := protocol.NewHandler(protocol.HandlerOptions{Project: cfg.Project, Credential: credential, BinarySHA256: binary, ConfigSHA256: digest, Clock: clock, Store: runtime.Store, Faults: faults, Ready: func(ctx context.Context) bool { return runtime.Ready(ctx) == nil }, BootstrapID: initial.User.UserID, BindingSHA256: runtime.BindingSHA256, Initialized: runtime.Initialized})
	if e != nil {
		return e
	}
	sender, e := syntheticSender(clock)
	if e != nil {
		return e
	}
	listener, e := net.Listen("tcp", fmt.Sprintf(":%d", cfg.PrivatePort))
	if e != nil {
		return e
	}
	socket, e := controlListener(cfg.ControlSocket)
	if e != nil {
		return errors.Join(e, listener.Close())
	}
	server := &http.Server{Handler: control, ReadHeaderTimeout: time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 16384}
	controlDone := make(chan error, 1)
	go func() { controlDone <- server.Serve(socket) }()
	controlContext, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-controlContext.Done():
		case <-controlDone:
			stop()
		}
	}()
	e = runtime.Serve(ctx, listener, faults.WrapHTTP(handler), sender)
	cancel()
	shutdown, finish := context.WithTimeout(context.Background(), 5*time.Second)
	ce := server.Shutdown(shutdown)
	finish()
	if ce != nil {
		ce = errors.Join(ce, server.Close())
	}
	return errors.Join(e, ce)
}
func controlListener(path string) (net.Listener, error) {
	parent := filepath.Dir(path)
	if e := os.MkdirAll(parent, 0700); e != nil {
		return nil, e
	}
	info, e := os.Lstat(parent)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("unsafe control directory")
	}
	if _, e = os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
		return nil, errors.New("existing control socket")
	}
	listener, e := net.Listen("unix", path)
	if e != nil {
		return nil, e
	}
	if e = os.Chmod(path, 0600); e != nil {
		return nil, errors.Join(e, listener.Close())
	}
	return listener, nil
}
func packagedZones() (*timezones.Catalog, error) {
	data, e := os.ReadFile("/usr/local/lib/umir/zoneinfo.zip")
	if e != nil {
		return nil, e
	}
	return timezones.New(data, "go1.26.9-embedded")
}
func syntheticSender(clock *protocol.Clock) (application.MailSender, error) {
	username, e := bootstrap.ReadPrivateFile("/run/umir-fixtures/secrets/smtp-username", 256)
	if e != nil {
		return nil, e
	}
	defer clear(username)
	password, e := bootstrap.ReadPrivateFile("/run/umir-fixtures/secrets/smtp-password", 256)
	if e != nil {
		return nil, e
	}
	defer clear(password)
	pem, e := bootstrap.ReadPrivateFile("/run/umir-fixtures/secrets/synthetic-ca.pem", 16384)
	if e != nil {
		return nil, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("invalid synthetic CA")
	}
	smtp, e := mail.NewSMTP(mail.SMTPConfig{Host: "smtp", Port: 2525, TLSMode: "starttls", Username: string(username), Password: string(password), From: "sender@umir.invalid", To: "feedback@umir.invalid", RootCAs: roots})
	if e != nil {
		return nil, e
	}
	sender, e := mail.NewRegistrationSMTP(smtp, mail.RegistrationMailConfig{OperatorName: "Synthetic Fixture", OperatorAddress: "Synthetic Network", SenderName: "Synthetic Auth"}, clock.Now, mailobserver.Observer{Transport: smtp})
	if e != nil {
		return nil, e
	}
	return sender, nil
}
