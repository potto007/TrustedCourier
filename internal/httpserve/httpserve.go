// Package httpserve runs an HTTP server until its context is done.
package httpserve

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// ErrorLog returns net/http's error log for a TLS listener. A failed TLS
// handshake is logged at Debug, not Warn: on a network listener any remote
// can fail one per connection before a credential is looked at, and the
// reason (no certificate loaded yet, a client that does not trust the CA or
// presents no client certificate) is already reported elsewhere. Everything
// else net/http reports stays at Warn.
func ErrorLog(logger *slog.Logger) *log.Logger {
	return log.New(handshakeErrorsToDebug{logger}, "", 0)
}

type handshakeErrorsToDebug struct{ log *slog.Logger }

func (h handshakeErrorsToDebug) Write(p []byte) (int, error) {
	msg := strings.TrimSuffix(string(p), "\n")
	level := slog.LevelWarn
	if strings.HasPrefix(msg, "http: TLS handshake error") {
		level = slog.LevelDebug
	}
	h.log.Log(context.Background(), level, msg)
	return len(p), nil
}

// shutdownTimeout bounds how long in-flight requests may take to finish.
const shutdownTimeout = 5 * time.Second

// Serve serves srv on ln until ctx is done, then shuts srv down gracefully.
// Connections still active after shutdownTimeout are closed. Their handlers
// may still be running when Serve returns.
func Serve(ctx context.Context, srv *http.Server, ln net.Listener) error {
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			if !errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			// A long stream must not hold the process up.
			_ = srv.Close()
		}
		if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
