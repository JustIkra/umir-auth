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

type boundedMailSender struct{ sender application.MailSender }

func (s boundedMailSender) Send(ctx context.Context, delivery application.MailDelivery) application.DeliveryResult {
	deliveryContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.sender.Send(deliveryContext, delivery)
}

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
	return httpapi.New(httpapi.Options{Accounts: r.Accounts, Signer: r.Signer, Clock: r.AccountOptions.Clock, Preauth: r.Preauth, ServiceKeys: keys, Ready: r.Ready, JWKSReady: func(context.Context) error { return r.Accounts.SigningReady() }})
}
func (r *Runtime) Serve(ctx context.Context, listener net.Listener, handler http.Handler, sender application.MailSender) error {
	return r.ServeWithMailProcessor(ctx, listener, handler, sender, accountsMailProcessor{})
}

type MailProcessor interface {
	ProcessMail(context.Context, *application.Accounts, application.MailSender) (bool, error)
}

type accountsMailProcessor struct{}

func (accountsMailProcessor) ProcessMail(ctx context.Context, accounts *application.Accounts, sender application.MailSender) (bool, error) {
	return accounts.ProcessMail(ctx, sender)
}

// backoff is the pause before retry n (1-based) of a failed worker: 1 s doubling
// to 30 s.
func backoff(n int) time.Duration {
	d := time.Second
	for i := 1; i < n && d < 30*time.Second; i++ {
		d *= 2
	}
	return min(d, 30*time.Second)
}

// supervise runs one worker until the context ends. A worker that returns an error
// is classified: a fatal one (state in doubt, store closed) is reported on fatal
// and ends the process; any other is logged, waited out with backoff and run
// again, and its recovery is logged when run next reports progress. The process
// never stays alive with a dead worker.
func (r *Runtime) supervise(ctx context.Context, name string, fatal chan<- error, run func(ctx context.Context, progress func()) error) {
	failures := 0
	progress := func() {
		if failures > 0 {
			r.Log.Info("worker recovered", "event", "auth.worker.recovered", "worker", name, "failures", failures)
			failures = 0
		}
	}
	for {
		err := run(ctx, progress)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			err = application.ErrAuthUnavailable
		}
		if r.Accounts.RecoveryPending() && !errors.Is(err, application.ErrRecoveryRequired) {
			// A request put Accounts in recovery; the worker only sees a plain
			// unavailable error from now on, but the process must restart.
			err = errors.Join(err, application.ErrRecoveryRequired)
		}
		if fatalWorkerError(err) {
			r.Log.Error("worker stopped the process", "event", "auth.worker.fatal", "worker", name, "error_class", errorClass(err))
			select {
			case fatal <- err:
			default:
			}
			return
		}
		failures++
		delay := backoff(failures)
		r.Log.Warn("worker degraded", "event", "auth.worker.degraded", "worker", name, "error_class", errorClass(err), "failure", failures, "retry_after_seconds", int64(delay/time.Second))
		if r.Pause.Wait(ctx, delay) != nil {
			return
		}
	}
}

// progressWaiter reports progress each time a worker's own loop waits, which it
// does after every completed pass.
type progressWaiter struct {
	progress func()
	inner    hostWaiter
}

func (w progressWaiter) Wait(ctx context.Context, d time.Duration) error {
	w.progress()
	return w.inner.Wait(ctx, d)
}

func (r *Runtime) ServeWithMailProcessor(ctx context.Context, listener net.Listener, handler http.Handler, sender application.MailSender, processor MailProcessor) error {
	if listener == nil || handler == nil || sender == nil || processor == nil || r.AccountOptions.Runtimes == nil {
		return ErrNotReady
	}
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	fatal := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Go(func() {
		r.supervise(work, "reconciliation", fatal, func(ctx context.Context, progress func()) error {
			return r.Accounts.RunReconciliation(ctx, progressWaiter{progress: progress})
		})
	})
	workers.Go(func() {
		r.supervise(work, "mail", fatal, func(ctx context.Context, progress func()) error {
			timer := time.NewTicker(100 * time.Millisecond)
			defer timer.Stop()
			logged := loggingMailSender{sender: boundedMailSender{sender}, log: r.Log}
			for {
				select {
				case <-ctx.Done():
					return nil
				case <-timer.C:
					attempt, stop := context.WithTimeout(ctx, 10*time.Second)
					_, mailErr := processor.ProcessMail(attempt, r.Accounts, logged)
					attemptErr := attempt.Err()
					stop()
					if mailErr == nil {
						progress()
						continue
					}
					if ctx.Err() != nil {
						return nil
					}
					interrupted := attemptErr != nil && (errors.Is(mailErr, context.DeadlineExceeded) || errors.Is(mailErr, context.Canceled))
					if interrupted && !errors.Is(mailErr, application.ErrUpdateOutcomeUnknown) && !errors.Is(mailErr, application.ErrRecoveryRequired) {
						recovery, cancel := context.WithTimeout(ctx, 5*time.Second)
						recoveryErr := r.Accounts.RecoverMail(recovery)
						cancel()
						if recoveryErr == nil {
							continue
						}
						mailErr = errors.Join(mailErr, recoveryErr)
					}
					return mailErr
				}
			}
		})
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	var err error
	var workerErr error
	select {
	case err = <-done:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	case workerErr = <-fatal:
		err = r.shutdown(server, done)
	case <-ctx.Done():
		err = r.shutdown(server, done)
	}
	cancel()
	workers.Wait()
	return errors.Join(err, workerErr)
}

func (r *Runtime) shutdown(server *http.Server, done <-chan error) error {
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	err := server.Shutdown(shutdown)
	stop()
	if err != nil {
		err = errors.Join(err, server.Close())
	}
	serveErr := <-done
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		err = errors.Join(err, serveErr)
	}
	return err
}
