// Package httpserve runs an HTTP server until its context is done.
package httpserve

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// shutdownTimeout bounds how long in-flight requests may take to finish.
const shutdownTimeout = 5 * time.Second

// Serve serves srv on ln until ctx is done, then shuts srv down gracefully.
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
			return err
		}
		if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
