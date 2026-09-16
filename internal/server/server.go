// Package server runs a TrustedCourier process from a config file.
package server

import (
	"context"
	"crypto/fips140"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/potto007/TrustedCourier/internal/access"
	"github.com/potto007/TrustedCourier/internal/acmecert"
	"github.com/potto007/TrustedCourier/internal/admin"
	"github.com/potto007/TrustedCourier/internal/agentapi"
	"github.com/potto007/TrustedCourier/internal/audit"
	"github.com/potto007/TrustedCourier/internal/certmanager"
	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/httpserve"
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
	// The Operator turns FIPS 140-3 mode on with GODEBUG=fips140=on (or
	// only) on the standard binary (ADR-0003); say which mode this is.
	log.Info("FIPS 140-3 mode", "fips140", onOff(fips140.Enabled()), "module", fips140.Version())

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
			certs = certmanager.New(log, "the Agent API")
			tlsConfig = certs.TLSConfig()
		}
		if agentLn, err = agentapi.Listen(cfg.AgentAPI, tlsConfig); err != nil {
			return err
		}
		defer func() { _ = agentLn.Close() }()
	}
	// The remote admin listener serves the Agent API's certificate when it
	// names the same Courier Keys, so an ACME renewal covers both; otherwise
	// its own Operator-supplied pair.
	var remoteLn net.Listener
	adminCerts := certs
	if cfg.Admin.Listen != "" {
		if !cfg.SharesAgentCertificate() {
			adminCerts = certmanager.New(log, "the remote admin listener")
		}
		if remoteLn, err = admin.ListenTLS(cfg.Admin.Listen, adminCerts, cfg.Admin.TLS.ClientCAs); err != nil {
			return err
		}
		defer func() { _ = remoteLn.Close() }()
	}
	// HTTP-01 validations arrive over plain HTTP on their own listener.
	var http01Ln net.Listener
	if acme := agentACME(cfg); acme != nil && acme.Challenge == config.ChallengeHTTP01 {
		if http01Ln, err = net.Listen("tcp", acme.HTTPListen); err != nil {
			return fmt.Errorf("listen on the ACME HTTP-01 address: %w", err)
		}
		defer func() { _ = http01Ln.Close() }()
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
		if agentTLS.ACME != nil {
			certs.StartACME(certmanager.ACME{
				Issuer:      acmecert.New(*agentTLS.ACME, secrets, log),
				Keys:        secrets,
				Domains:     agentTLS.ACME.Domains,
				Certificate: agentTLS.Certificate,
				Key:         agentTLS.Key,
			})
		} else {
			certs.Start(operatorPair(secrets, agentTLS.Certificate, agentTLS.Key))
		}
		defer certs.Close()
	}
	if adminCerts != nil && adminCerts != certs {
		adminCerts.Start(operatorPair(secrets, cfg.Admin.TLS.Certificate, cfg.Admin.TLS.Key))
		defer adminCerts.Close()
	}

	// When either API stops, stop the other.
	serveCtx, stopServing := context.WithCancel(ctx)
	defer stopServing()
	errc := make(chan error, 3)
	serving := 1
	agent := admin.AgentAPI{Socket: cfg.AgentAPI.Socket}
	if certs != nil {
		agent.Certificate = certificateStatus{certs}
	}
	// The HTTP-01 listener matters for seconds per renewal, so its failure
	// is logged and never stops the APIs.
	if http01Ln != nil {
		http01Srv := &http.Server{
			Handler:           certs.HTTP01Handler(),
			ReadHeaderTimeout: 10 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       time.Minute,
			MaxHeaderBytes:    64 << 10,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
		}
		go func() {
			if err := httpserve.Serve(serveCtx, http01Srv, http01Ln); err != nil {
				log.Error("ACME HTTP-01 challenge listener stopped; HTTP-01 validations fail until a restart", "error", err)
			}
		}()
		log.Info("ACME HTTP-01 challenge listener listening", "address", boundAddress(agentACME(cfg).HTTPListen, http01Ln.Addr()))
	}
	if agentLn != nil && cfg.AgentAPI.Socket == "" {
		scheme := "http://"
		if cfg.AgentAPI.TLS != nil {
			scheme = "https://"
		}
		agent.URL = scheme + boundAddress(cfg.AgentAPI.Listen, agentLn.Addr())
	}
	var remoteCertificate admin.CertificateStatus
	if remoteLn != nil {
		remoteCertificate = certificateStatus{adminCerts}
	}
	adminSrv := admin.NewServer(svc, plugins, auditLog, running, agent, remoteCertificate, log)
	go func() { errc <- adminSrv.Serve(serveCtx, ln) }()
	log.Info("admin API listening", "socket", cfg.Admin.Socket)
	if remoteLn != nil {
		serving++
		go func() { errc <- adminSrv.ServeTLS(serveCtx, remoteLn) }()
		log.Info("remote admin API listening", "url", "https://"+boundAddress(cfg.Admin.Listen, remoteLn.Addr()))
	}
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

// operatorPair fetches an Operator-supplied certificate and key from their
// Backend.
func operatorPair(secrets *resolver.Resolver, certificate, key config.CourierKey) certmanager.Fetch {
	return func(ctx context.Context) (*secret.Secret, *secret.Secret, error) {
		cert, err := secrets.CourierKey(ctx, certificate)
		if err != nil {
			return nil, nil, fmt.Errorf("fetch the TLS certificate: %w", err)
		}
		k, err := secrets.CourierKey(ctx, key)
		if err != nil {
			return cert, nil, fmt.Errorf("fetch the TLS key: %w", err)
		}
		return cert, k, nil
	}
}

// agentACME returns the Agent API's ACME config, or nil without one.
func agentACME(cfg *config.Config) *config.ACME {
	if cfg.AgentAPI.TLS == nil {
		return nil
	}
	return cfg.AgentAPI.TLS.ACME
}

// certificateStatus reports the certificate manager's state to the admin
// API.
type certificateStatus struct{ certs *certmanager.Manager }

func (c certificateStatus) Status() admin.TLSCertificateStatus {
	s := c.certs.Status()
	out := admin.TLSCertificateStatus{Loaded: s.Loaded, Detail: s.Detail, RenewalError: s.RenewalError}
	if !s.NotAfter.IsZero() {
		out.NotAfter = s.NotAfter.UTC().Format(time.RFC3339)
	}
	if !s.RenewAt.IsZero() {
		out.RenewAt = s.RenewAt.UTC().Format(time.RFC3339)
	}
	return out
}

// boundAddress is the configured listen address with the port actually
// bound, so a port of 0 is reported as the port chosen, and 0.0.0.0 stays
// 0.0.0.0 rather than the dual-stack [::] the kernel reports.
func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

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
