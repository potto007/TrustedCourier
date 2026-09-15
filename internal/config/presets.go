package config

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

// EnvSource is what an environment variable tc env prints holds.
type EnvSource string

// Environment variable sources, in the order tc env prints them.
const (
	// EnvBaseURL is the Proxy Delivery route to one of the Upstreams.
	EnvBaseURL EnvSource = "base_url"
	// EnvUsername is a basic auth template's literal username.
	EnvUsername EnvSource = "username"
	// EnvPassword is a basic auth template's literal password.
	EnvPassword EnvSource = "password"
	// EnvAgentToken is the Agent Token, which goes where the Secret would.
	EnvAgentToken EnvSource = "agent_token"
)

var envSources = []EnvSource{EnvBaseURL, EnvUsername, EnvPassword, EnvAgentToken}

// EnvVar is one environment variable an Agent needs for a Secret Name.
type EnvVar struct {
	Name   string
	Source EnvSource
}

//go:embed presets.yaml
var presetsYAML []byte

// preset is a validated Preset: what applying it gives a Secret Name.
type preset struct {
	template  InjectionTemplate
	upstreams map[string]Upstream
	env       []EnvVar
}

type filePreset struct {
	InjectionTemplate *fileInjectionTemplate  `yaml:"injection_template"`
	Upstreams         map[string]fileUpstream `yaml:"upstreams"`
	Env               map[string]string       `yaml:"env"`
}

// builtinPresets are the Presets in presets.yaml.
var builtinPresets = sync.OnceValues(func() (map[string]preset, error) {
	presets, err := parsePresets(presetsYAML)
	if err != nil {
		return nil, fmt.Errorf("built-in presets: %w", err)
	}
	return presets, nil
})

// parsePresets decodes and validates a Preset file strictly, as the config
// file is decoded.
func parsePresets(data []byte) (map[string]preset, error) {
	var raw map[string]filePreset
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	out := make(map[string]preset, len(raw))
	for _, name := range slices.Sorted(maps.Keys(raw)) {
		p, err := raw[name].validate()
		if !namePattern.MatchString(name) {
			err = errors.New("invalid name")
		}
		if err != nil {
			return nil, fmt.Errorf("preset %q: %w", name, err)
		}
		out[name] = p
	}
	return out, nil
}

func (p filePreset) validate() (preset, error) {
	switch {
	case p.InjectionTemplate == nil:
		return preset{}, errors.New("injection_template is required")
	case len(p.Upstreams) == 0:
		return preset{}, errors.New("upstreams is required")
	}
	tmpl, err := p.InjectionTemplate.validate()
	if err != nil {
		return preset{}, fmt.Errorf("injection_template: %w", err)
	}
	for name, up := range p.Upstreams {
		if up.CABundle != "" {
			return preset{}, fmt.Errorf("Upstream %q: a Preset cannot set ca_bundle", name)
		}
	}
	upstreams, err := validateUpstreams(p.Upstreams, "")
	if err != nil {
		return preset{}, err
	}
	env, err := validateEnv(p.Env, tmpl)
	if err != nil {
		return preset{}, fmt.Errorf("env: %w", err)
	}
	return preset{template: tmpl, upstreams: upstreams, env: env}, nil
}

var envNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)

// validateEnv checks that env names a base URL, the Agent Token, and only the
// literal basic auth fields t has, each once.
func validateEnv(env map[string]string, t InjectionTemplate) ([]EnvVar, error) {
	allowed := map[EnvSource]bool{EnvBaseURL: true, EnvAgentToken: true}
	if b := t.BasicAuth; b != nil {
		allowed[EnvUsername] = !b.SecretIsUsername
		allowed[EnvPassword] = b.SecretIsUsername
	}
	var out []EnvVar
	seen := map[EnvSource]bool{}
	for _, name := range slices.Sorted(maps.Keys(env)) {
		source := EnvSource(env[name])
		switch {
		case !envNamePattern.MatchString(name):
			return nil, fmt.Errorf("invalid variable name %q: use up to 64 upper-case letters, digits, or '_', not starting with a digit", name)
		case !slices.Contains(envSources, source):
			return nil, fmt.Errorf("%s: unknown source %q (want base_url, agent_token, username, or password)", name, source)
		case !allowed[source]:
			return nil, fmt.Errorf("%s: the Injection Template has no literal %s", name, source)
		case seen[source]:
			return nil, fmt.Errorf("%s: %s is named twice", name, source)
		}
		seen[source] = true
		out = append(out, EnvVar{Name: name, Source: source})
	}
	for _, source := range []EnvSource{EnvBaseURL, EnvAgentToken} {
		if !seen[source] {
			return nil, fmt.Errorf("no variable holds %s", source)
		}
	}
	sortEnv(out)
	return out, nil
}

// defaultEnv names the variables for a Secret Name without a Preset after the
// Secret Name, such as MY_API_BASE_URL and MY_API_API_KEY for my-api.
func defaultEnv(secretName string, t InjectionTemplate) []EnvVar {
	prefix := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' {
			return r - 'a' + 'A'
		}
		if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, secretName)
	if prefix[0] >= '0' && prefix[0] <= '9' {
		prefix = "_" + prefix
	}
	env := []EnvVar{{prefix + "_BASE_URL", EnvBaseURL}}
	switch b := t.BasicAuth; {
	case b == nil:
		env = append(env, EnvVar{prefix + "_API_KEY", EnvAgentToken})
	case b.SecretIsUsername:
		env = append(env, EnvVar{prefix + "_USERNAME", EnvAgentToken})
		if b.Password != "" {
			env = append(env, EnvVar{prefix + "_PASSWORD", EnvPassword})
		}
	default:
		if b.Username != "" {
			env = append(env, EnvVar{prefix + "_USERNAME", EnvUsername})
		}
		env = append(env, EnvVar{prefix + "_PASSWORD", EnvAgentToken})
	}
	sortEnv(env)
	return env
}

func sortEnv(env []EnvVar) {
	slices.SortStableFunc(env, func(a, b EnvVar) int {
		return slices.Index(envSources, a.Source) - slices.Index(envSources, b.Source)
	})
}
