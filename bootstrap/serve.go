package bootstrap

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/httpapi"
	"github.com/JustIkra/umir-auth/internal/application"
)

type hostWaiter struct{}

func (hostWaiter) Wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (r *Runtime) Handler(keys map[string]string) (http.Handler, error) {
	return httpapi.New(httpapi.Options{Accounts: r.Accounts, Signer: r.Signer, Clock: r.AccountOptions.Clock, Preauth: r.Preauth, ServiceKeys: keys, Ready: r.Ready})
}
func (r *Runtime) Serve(ctx context.Context, listener net.Listener, handler http.Handler, sender application.MailSender) error {
	if listener == nil || handler == nil || sender == nil || r.AccountOptions.Runtimes == nil {
		return ErrNotReady
	}
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	workers.Go(func() {
		if err := r.Accounts.RunReconciliation(work, hostWaiter{}); err != nil && work.Err() == nil {
			r.failWorker(err)
		}
	})
	workers.Go(func() {
		timer := time.NewTicker(100 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case <-work.Done():
				return
			case <-timer.C:
				attempt, stop := context.WithTimeout(work, 5*time.Second)
				_, mailErr := r.Accounts.ProcessMail(attempt, sender)
				if mailErr != nil && work.Err() == nil {
					r.failWorker(mailErr)
					stop()
					return
				}
				stop()
			}
		}
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	var err error
	select {
	case err = <-done:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	case <-ctx.Done():
		shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
		err = server.Shutdown(shutdown)
		stop()
		if err != nil {
			err = errors.Join(err, server.Close())
		}
		serveErr := <-done
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			err = errors.Join(err, serveErr)
		}
	}
	cancel()
	workers.Wait()
	return err
}
