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

	"sync"

	"github.com/JustIkra/umir-auth/bootstrap"
	mail "github.com/JustIkra/umir-auth/internal/adapters/mail"
	"github.com/JustIkra/umir-auth/internal/adapters/runtimehttp"
	"github.com/JustIkra/umir-auth/internal/adapters/timezones"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/tests/fixtures/profiles"
	"github.com/JustIkra/umir-auth/tests/fixtures/protocol"
	"github.com/JustIkra/umir-auth/tests/mailobserver"
)

func main() {
	var e error
	switch {
	case len(os.Args) == 2 && os.Args[1] == "serve":
		e = serve("")
	case len(os.Args) == 4 && os.Args[1] == "serve-profile" && os.Args[2] == "--profile" && protocol.AuthProfile(os.Args[3]):
		e = serve(os.Args[3])
	case len(os.Args) == 2 && os.Args[1] == "probe-second-writer":
		code, err := profiles.ProbeSecondWriter()
		if err != nil {
			os.Exit(1)
		}
		os.Exit(code)
	case len(os.Args) == 2 && os.Args[1] == "healthcheck":
		e = protocol.Healthcheck()
	default:
		e = errors.New("unsupported command")
	}
	if e != nil {
		if _, e = fmt.Fprintln(os.Stderr, "Auth fixture unavailable"); e != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}
}
func serve(selector string) (result error) {
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
	profileDigest := ""
	if selector != "" {
		_, profileDigest, e = protocol.LoadProfile(cfg, selector)
		if e != nil {
			return e
		}
		clock, e = profiles.RestoreClock(selector, cfg.Project, clock)
		if e != nil {
			return e
		}
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
	owner, e := profiles.NewOwner(cfg, digest, profileDigest, credential, clock, zones)
	if e != nil {
		return e
	}
	socket, e := controlListener(cfg.ControlSocket)
	if e != nil {
		return e
	}
	var controlMu sync.RWMutex
	var normalControl http.Handler
	supervisor := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.ProfilePath {
			owner.ServeHTTP(w, r)
			return
		}
		controlMu.RLock()
		handler := normalControl
		controlMu.RUnlock()
		if handler == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	})
	server := &http.Server{Handler: supervisor, ReadHeaderTimeout: time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 16384}
	controlDone := make(chan error, 1)
	go func() { controlDone <- server.Serve(socket) }()
	defer func() {
		shutdown, finish := context.WithTimeout(context.Background(), 5*time.Second)
		ce := server.Shutdown(shutdown)
		finish()
		if ce != nil {
			ce = errors.Join(ce, server.Close())
		}
		se := <-controlDone
		if errors.Is(se, http.ErrServerClosed) {
			se = nil
		}
		result = errors.Join(result, ce, se)
	}()
	openContext, openCancel := context.WithTimeout(ctx, 10*time.Second)
	options := bootstrap.Options{StateFile: cfg.StateFile, SecretsDir: filepath.Join(filepath.Dir(cfg.StateFile), "secrets"), Initial: &initial.User, Password: string(password), Clock: clock, TimeZones: zones, Runtimes: peers}
	var runtime *bootstrap.Runtime
	if selector != "" {
		runtime, e = owner.Admit(openContext, selector, options)
	} else {
		runtime, e = bootstrap.Open(openContext, options)
	}
	openCancel()
	if e != nil {
		return e
	}
	if runtime == nil {
		expired, finish := context.WithTimeout(ctx, 300*time.Second)
		defer finish()
		<-expired.Done()
		return nil
	}
	defer func() {
		if ce := runtime.Close(); ce != nil {
			stop()
		}
	}()
	faults := &protocol.Faults{}
	accountOptions := runtime.AccountOptions
	accountOptions.Repository = &protocol.FaultRepository{Store: runtime.Store, Faults: faults}
	runtime.Accounts, e = application.NewAccounts(ctx, accountOptions)
	if e != nil {
		return e
	}
	runtime.AccountOptions = accountOptions
	if selector != "" {
		if e = owner.Bind(ctx, runtime); e != nil {
			return e
		}
	} else {
		owner.BindOrdinary(runtime)
	}
	defer func() {
		checkpointCtx, finish := context.WithTimeout(context.Background(), 5*time.Second)
		result = errors.Join(result, owner.Checkpoint(checkpointCtx))
		finish()
	}()
	if e = peers.Bind(runtime.Accounts); e != nil {
		return e
	}
	handler, e := runtime.Handler(map[string]string{"gateway": keys["gateway-auth"], "serving": keys["serving-auth"], "warehouse": keys["auth-warehouse"], "feedback": keys["feedback-auth"]})
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
	controlMu.Lock()
	normalControl = control
	controlMu.Unlock()
	serviceKeys := map[string]string{"gateway": keys["gateway-auth"], "serving": keys["serving-auth"], "warehouse": keys["auth-warehouse"], "feedback": keys["feedback-auth"]}
	return runtime.Serve(ctx, listener, faults.WrapHTTP(owner.WrapBusiness(handler, serviceKeys)), sender)
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
