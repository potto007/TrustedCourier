// Package config loads and validates the TrustedCourier config file into an
// immutable snapshot.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// DefaultAdminSocket is where the admin API listens when the config names no
// socket.
const DefaultAdminSocket = "/run/trustedcourier/admin.sock"

// Config is a fully validated config snapshot. Treat it as read-only.
type Config struct {
	// DataDir holds the SQLite database.
	DataDir string
	Admin   Admin
	// Policies by name.
	Policies map[string]Policy
}

// Admin configures the admin API.
type Admin struct {
	// Socket is the unix socket path of the admin API.
	Socket string
	// AllowedUIDs are the local users allowed to connect to Socket.
	AllowedUIDs []int
}

// Policy states which Secret Names an Agent Token may use and how.
type Policy struct {
	Name    string
	Secrets []SecretAccess
}

// SecretAccess allows one Secret Name in the listed Delivery modes.
type SecretAccess struct {
	SecretName string
	Delivery   []DeliveryMode
}

// DeliveryMode is proxy or reveal.
type DeliveryMode string

// Delivery modes.
const (
	DeliveryProxy  DeliveryMode = "proxy"
	DeliveryReveal DeliveryMode = "reveal"
)

type fileConfig struct {
	DataDir  string                `yaml:"data_dir"`
	Admin    fileAdmin             `yaml:"admin"`
	Policies map[string]filePolicy `yaml:"policies"`
}

type fileAdmin struct {
	Socket      string `yaml:"socket"`
	AllowedUIDs []int  `yaml:"allowed_uids"`
}

type filePolicy struct {
	Secrets []fileSecretAccess `yaml:"secrets"`
}

type fileSecretAccess struct {
	Name     string   `yaml:"name"`
	Delivery []string `yaml:"delivery"`
}

// Load reads and validates the config file at path. Relative paths in the
// file are resolved against the file's directory.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg, err := raw.validate(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func (raw fileConfig) validate(baseDir string) (*Config, error) {
	cfg := &Config{Policies: make(map[string]Policy, len(raw.Policies))}

	if raw.DataDir == "" {
		return nil, errors.New("data_dir is required")
	}
	cfg.DataDir = resolve(baseDir, raw.DataDir)

	cfg.Admin.Socket = DefaultAdminSocket
	if raw.Admin.Socket != "" {
		cfg.Admin.Socket = resolve(baseDir, raw.Admin.Socket)
	}
	cfg.Admin.AllowedUIDs = raw.Admin.AllowedUIDs
	if len(cfg.Admin.AllowedUIDs) == 0 {
		cfg.Admin.AllowedUIDs = []int{os.Getuid()}
	}

	for name, p := range raw.Policies {
		policy := Policy{Name: name}
		for _, s := range p.Secrets {
			access := SecretAccess{SecretName: s.Name}
			for _, mode := range s.Delivery {
				access.Delivery = append(access.Delivery, DeliveryMode(mode))
			}
			policy.Secrets = append(policy.Secrets, access)
		}
		cfg.Policies[name] = policy
	}
	return cfg, nil
}

func resolve(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}
