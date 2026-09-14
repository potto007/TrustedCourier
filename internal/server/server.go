// Package server runs a TrustedCourier process from a config file.
package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/potto007/TrustedCourier/internal/access"
	"github.com/potto007/TrustedCourier/internal/admin"
	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/pluginhost"
	"github.com/potto007/TrustedCourier/internal/store"
)

// Run loads the config at configPath and serves until ctx is done. The
// Operator Credential is written to stdout on first boot only; logs go to
// stderr.
func Run(ctx context.Context, configPath string, stdout, stderr io.Writer) error {
	log := slog.New(slog.NewTextHandler(stderr, nil))

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	plugins, err := pluginhost.New(cfg, stderr, log)
	if err != nil {
		return err
	}
	db, err := store.Open(ctx, cfg.DataDir)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Bind before creating the Operator Credential: it is shown only once,
	// so nothing that can still fail may come between showing it and serving.
	ln, err := admin.Listen(cfg.Admin.Socket, cfg.Admin.AllowedUIDs)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()

	svc := access.New(db, cfg)
	if err := svc.EnsureOperatorCredential(ctx, func(credential string) error {
		_, err := fmt.Fprintf(stdout, "Operator Credential (shown once; store it now, it cannot be shown again):\n%s\n", credential)
		return err
	}); err != nil {
		return err
	}

	pluginCtx, stopPlugins := context.WithCancel(ctx)
	defer func() {
		stopPlugins()
		plugins.Wait()
	}()
	plugins.Start(pluginCtx)

	log.Info("admin API listening", "socket", cfg.Admin.Socket)
	return admin.NewServer(svc, plugins, cfg.Admin.AllowedUIDs, log).Serve(ctx, ln)
}
