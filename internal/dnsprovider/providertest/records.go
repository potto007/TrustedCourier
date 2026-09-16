// Package providertest fakes the DNS provider APIs the built-in providers
// call, for the provider tests and the e2e harness. Each fake checks the
// credentials it is given and keeps its records in a Records.
package providertest

import (
	"slices"
	"sort"
	"strings"
	"sync"
)

// Records is what a fake provider holds: the zones it serves and the TXT
// values at each name. Names are lowercase without a trailing dot.
type Records struct {
	mu    sync.Mutex
	zones []string
	txt   map[string][]string
	// OnChange, when set, is called with the name and its values after
	// every change, so the e2e harness can mirror the records into a name
	// server.
	OnChange func(name string, values []string)
}

// NewRecords returns a Records serving zones, holding no TXT records.
func NewRecords(zones ...string) *Records {
	r := &Records{txt: map[string][]string{}}
	for _, z := range zones {
		r.zones = append(r.zones, normalize(z))
	}
	sort.Strings(r.zones)
	return r
}

// Zones lists the zones, sorted.
func (r *Records) Zones() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.zones)
}

// HasZone reports whether zone is served.
func (r *Records) HasZone(zone string) bool {
	return slices.Contains(r.Zones(), normalize(zone))
}

// ZoneOf returns the zone that holds name: the longest zone name is a
// suffix of, or empty.
func (r *Records) ZoneOf(name string) string {
	name = normalize(name)
	var best string
	for _, z := range r.Zones() {
		if (name == z || strings.HasSuffix(name, "."+z)) && len(z) > len(best) {
			best = z
		}
	}
	return best
}

// TXT returns the TXT values at name, unquoted, or nil.
func (r *Records) TXT(name string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.txt[normalize(name)])
}

// Names lists every name that holds TXT values, sorted.
func (r *Records) Names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.txt))
	for n := range r.txt {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// SetTXT replaces the TXT values at name; none deletes the set.
func (r *Records) SetTXT(name string, values []string) {
	name = normalize(name)
	r.mu.Lock()
	if len(values) == 0 {
		delete(r.txt, name)
	} else {
		r.txt[name] = slices.Clone(values)
	}
	onChange := r.OnChange
	r.mu.Unlock()
	if onChange != nil {
		onChange(name, slices.Clone(values))
	}
}

// AddTXT appends value to the TXT values at name.
func (r *Records) AddTXT(name, value string) {
	r.SetTXT(name, append(r.TXT(name), value))
}

// RemoveTXT removes value from the TXT values at name.
func (r *Records) RemoveTXT(name, value string) {
	values := r.TXT(name)
	if i := slices.Index(values, value); i >= 0 {
		values = slices.Delete(values, i, i+1)
	}
	r.SetTXT(name, values)
}

func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// unquote strips one pair of surrounding double quotes, as TXT values are
// carried by most APIs.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
