// Package server runs a TrustedCourier process from a config file.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/potto007/TrustedCourier/internal/access"
	"github.com/potto007/TrustedCourier/internal/admin"
	"github.com/potto007/TrustedCourier/internal/agentapi"
	"github.com/potto007/TrustedCourier/internal/audit"
	"github.com/potto007/TrustedCourier/internal/certmanager"
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
	var certs *certmanager.Manager
	if cfg.AgentAPI.Served() {
		var tlsConfig *tls.Config
		if cfg.AgentAPI.TLS != nil {
			certs = certmanager.New(log)
			tlsConfig = certs.TLSConfig()
		}
		if agentLn, err = agentapi.Listen(cfg.AgentAPI, tlsConfig); err != nil {
			return err
		}
		defer func() { _ = agentLn.Close() }()
	}

	running := config.NewRunning(cfg)
	svc := access.New(db, running)
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

	// The Agent API refuses Deliveries until the audit signing key is loaded,
	// and while Audit Records cannot be stored. Once both APIs have drained,
	// the last records are stored and signed before the database closes.
	secrets := resolver.New(plugins, running)
	// Runs once both APIs have drained, so no Delivery still needs the cache.
	defer secrets.Close()
	if key := cfg.Audit.SigningKey; key != nil {
		auditLog.Start(func(ctx context.Context) (*secret.Secret, error) { return secrets.CourierKey(ctx, *key) })
	}
	defer func() {
		if err := auditLog.Close(); err != nil {
			log.Error("closing the audit log failed", "error", err)
		}
	}()
	// The TLS listener completes no handshake until the certificate is
	// loaded from its Backend (ADR-0001).
	if certs != nil {
		agentTLS := *cfg.AgentAPI.TLS
		certs.Start(func(ctx context.Context) (*secret.Secret, *secret.Secret, error) {
			certificate, err := secrets.CourierKey(ctx, agentTLS.Certificate)
			if err != nil {
				return nil, nil, fmt.Errorf("fetch the TLS certificate: %w", err)
			}
			key, err := secrets.CourierKey(ctx, agentTLS.Key)
			if err != nil {
				certificate.Release()
				return nil, nil, fmt.Errorf("fetch the TLS key: %w", err)
			}
			return certificate, key, nil
		})
		defer certs.Close()
	}

	// When either API stops, stop the other.
	serveCtx, stopServing := context.WithCancel(ctx)
	defer stopServing()
	errc := make(chan error, 2)
	serving := 1
	agent := admin.AgentAPI{Socket: cfg.AgentAPI.Socket}
	if certs != nil {
		agent.Certificate = certs
	}
	if agentLn != nil && cfg.AgentAPI.Socket == "" {
		scheme := "http://"
		if cfg.AgentAPI.TLS != nil {
			scheme = "https://"
		}
		agent.URL = scheme + boundAddress(cfg.AgentAPI.Listen, agentLn.Addr())
	}
	go func() {
		errc <- admin.NewServer(svc, plugins, auditLog, running, agent, log).Serve(serveCtx, ln)
	}()
	log.Info("admin API listening", "socket", cfg.Admin.Socket)
	if agentLn != nil {
		serving++
		agentSrv := agentapi.NewServer(svc, secrets, auditLog, running, log)
		go func() { errc <- agentSrv.Serve(serveCtx, agentLn, cfg.AgentAPI.TLS != nil) }()
		if agent.Socket != "" {
			log.Info("Agent API listening", "socket", agent.Socket)
		} else {
			log.Info("Agent API listening", "url", agent.URL)
		}
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

// boundAddress is the configured listen address with the port actually
// bound, so a port of 0 is reported as the port chosen, and 0.0.0.0 stays
// 0.0.0.0 rather than the dual-stack [::] the kernel reports.
func boundAddress(configured string, bound net.Addr) string {
	host, _, err := net.SplitHostPort(configured)
	if err != nil {
		return bound.String()
	}
	_, port, err := net.SplitHostPort(bound.String())
	if err != nil {
		return bound.String()
	}
	return net.JoinHostPort(host, port)
}
