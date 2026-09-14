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
	db, err := store.Open(ctx, cfg.DataDir)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer func() { _ = db.Close() }()

	svc := access.New(db, cfg)
	credential, err := svc.EnsureOperatorCredential(ctx)
	if err != nil {
		return err
	}
	if credential != "" {
		fmt.Fprintf(stdout, "Operator Credential (shown once; store it now, it cannot be shown again):\n%s\n", credential)
	}

	ln, err := admin.Listen(cfg.Admin.Socket)
	if err != nil {
		return err
	}
	log.Info("admin API listening", "socket", cfg.Admin.Socket)
	return admin.NewServer(svc, cfg.Admin.AllowedUIDs, log).Serve(ctx, ln)
}
