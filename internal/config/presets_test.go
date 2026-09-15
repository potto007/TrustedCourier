package config

import (
	"maps"
	"slices"
	"testing"
)

func TestBuiltInPresetsAreValid(t *testing.T) {
	presets, err := builtinPresets()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := slices.Sorted(maps.Keys(presets)), []string{"anthropic", "github", "openai"}; !slices.Equal(got, want) {
		t.Fatalf("built-in Presets = %v, want %v", got, want)
	}
}

// A Preset is data in the Preset format, so a new one, of any Injection
// Template kind, needs only a new entry.
func TestAddingAPresetNeedsOnlyData(t *testing.T) {
	presets, err := parsePresets([]byte(`
twilio:
  injection_template:
    basic_auth:
      username: AC123
      password: "{secret}"
  upstreams:
    api:
      url: https://api.twilio.com/2010-04-01
  env:
    TWILIO_API_URL: base_url
    TWILIO_ACCOUNT_SID: username
    TWILIO_AUTH_TOKEN: agent_token
weather:
  injection_template:
    query:
      name: appid
  upstreams:
    api:
      url: https://api.openweathermap.org
  env:
    WEATHER_BASE_URL: base_url
    WEATHER_API_KEY: agent_token
`))
	if err != nil {
		t.Fatal(err)
	}
	if p := presets["twilio"]; p.template.BasicAuth == nil || p.upstreams["api"].Host != "api.twilio.com" {
		t.Errorf("twilio = %+v, want a basic auth template pinned to api.twilio.com", p)
	}
	if p := presets["weather"]; p.template.Query == nil || p.template.Query.Name != "appid" {
		t.Errorf("weather = %+v, want a query template on appid", p)
	}
}

func TestPresetsAreValidated(t *testing.T) {
	const template = "  injection_template:\n    header:\n      name: X-Key\n      value: \"{secret}\"\n"
	const upstreams = "  upstreams:\n    api:\n      url: https://api.example.com\n"
	const env = "  env:\n    EX_BASE_URL: base_url\n    EX_KEY: agent_token\n"
	cases := map[string]string{
		"unknown field":            "ex:\n" + template + upstreams + env + "  extra: 1\n",
		"no Injection Template":    "ex:\n" + upstreams + env,
		"no Upstreams":             "ex:\n" + template + env,
		"CA bundle":                "ex:\n" + template + upstreams + "      ca_bundle: ca.pem\n" + env,
		"no base_url":              "ex:\n" + template + upstreams + "  env:\n    EX_KEY: agent_token\n",
		"no agent_token":           "ex:\n" + template + upstreams + "  env:\n    EX_BASE_URL: base_url\n",
		"unknown source":           "ex:\n" + template + upstreams + env + "    EX_OTHER: region\n",
		"invalid variable name":    "ex:\n" + template + upstreams + "  env:\n    ex-base: base_url\n    EX_KEY: agent_token\n",
		"username without literal": "ex:\n" + template + upstreams + env + "    EX_USER: username\n",
		"invalid Preset name":      "\"bad name\":\n" + template + upstreams + env,
	}
	for name, doc := range cases {
		if _, err := parsePresets([]byte(doc)); err == nil {
			t.Errorf("%s: parsePresets accepted\n%s", name, doc)
		}
	}
}
