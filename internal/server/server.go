// Package server runs a TrustedCourier process from a config file.
package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/potto007/TrustedCourier/internal/access"
	"github.com/potto007/TrustedCourier/internal/admin"
	"github.com/potto007/TrustedCourier/internal/agentapi"
	"github.com/potto007/TrustedCourier/internal/audit"
	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/pluginhost"
	"github.com/potto007/TrustedCourier/internal/resolver"
	"github.com/potto007/TrustedCourier/internal/secret"
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
	// Audit Records stream to stdout, which carries nothing else once the
	// Operator Credential has been shown.
	auditLog, err := audit.Open(ctx, db, stdout, audit.Checkpoints{
		Records:  cfg.Audit.CheckpointRecords,
		Interval: cfg.Audit.CheckpointInterval,
	}, log)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	// Bind before creating the Operator Credential: it is shown only once,
	// so nothing that can still fail may come between showing it and serving.
	ln, err := admin.Listen(cfg.Admin.Socket, cfg.Admin.AllowedUIDs)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()
	var agentLn net.Listener
	if cfg.AgentAPI.Listen != "" {
		if agentLn, err = agentapi.Listen(cfg.AgentAPI.Listen); err != nil {
			return err
		}
		defer func() { _ = agentLn.Close() }()
	}

	svc := access.New(db, cfg)
	if err := svc.EnsureOperatorCredential(ctx, func(credential string) error {
		_, err := fmt.Fprintf(stdout, "Operator Credential (shown once; store it now, it cannot be shown again):\n%s\n", credential)
		return err
	}); err != nil {
		return err
	}

	// Plugins outlive the signal until both APIs have drained, so in-flight
	// Deliveries can still fetch their Secrets.
	pluginCtx, stopPlugins := context.WithCancel(context.WithoutCancel(ctx))
	defer func() {
		stopPlugins()
		plugins.Wait()
	}()
	plugins.Start(pluginCtx)

	// The Agent API refuses Deliveries until the audit signing key is loaded.
	// Once both APIs have drained, the last records are signed before the
	// database closes.
	secrets := resolver.New(cfg, plugins)
	if key := cfg.Audit.SigningKey; key != nil {
		auditLog.Start(func(ctx context.Context) (*secret.Secret, error) { return secrets.CourierKey(ctx, *key) })
	}
	defer func() {
		if err := auditLog.Close(); err != nil {
			log.Error("final audit checkpoint failed", "error", err)
		}
	}()

	// When either API stops, stop the other.
	serveCtx, stopServing := context.WithCancel(ctx)
	defer stopServing()
	errc := make(chan error, 2)
	serving := 1
	var agentURL string
	if agentLn != nil {
		agentURL = "http://" + agentLn.Addr().String()
	}
	go func() {
		errc <- admin.NewServer(svc, plugins, auditLog, cfg, agentURL, log).Serve(serveCtx, ln)
	}()
	log.Info("admin API listening", "socket", cfg.Admin.Socket)
	if agentLn != nil {
		serving++
		agent := agentapi.NewServer(svc, secrets, auditLog, cfg, log)
		go func() { errc <- agent.Serve(serveCtx, agentLn) }()
		log.Info("Agent API listening", "address", agentLn.Addr().String())
	}
	var firstErr error
	for range serving {
		if err := <-errc; err != nil && firstErr == nil {
			firstErr = err
		}
		stopServing()
	}
	return firstErr
}
