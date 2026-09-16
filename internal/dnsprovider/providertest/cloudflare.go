package providertest

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// Cloudflare fakes the Cloudflare v4 API: zone lookup by name and TXT
// record listing, creation, and deletion, behind an API token.
type Cloudflare struct {
	*httptest.Server
	Records *Records

	mu      sync.Mutex
	nextID  int
	records map[string]cloudflareRecord // by record id
}

type cloudflareRecord struct {
	ID, ZoneID, Name, Content string
}

// NewCloudflare serves records over TLS, accepting token as the API token.
// Close it when done.
func NewCloudflare(records *Records, token string) *Cloudflare {
	f := &Cloudflare{Records: records, records: map[string]cloudflareRecord{}}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			cloudflareError(w, http.StatusForbidden, 10000, "Authentication error")
			return
		}
		f.handle(w, r)
	}))
	return f
}

func (f *Cloudflare) handle(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/client/v4")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && path == "/zones":
		var result []map[string]string
		if name := r.URL.Query().Get("name"); f.Records.HasZone(name) {
			result = append(result, map[string]string{"id": zoneID(name), "name": normalize(name)})
		}
		cloudflareOK(w, result)
	case r.Method == http.MethodGet && len(parts) == 3 && parts[0] == "zones" && parts[2] == "dns_records":
		q := r.URL.Query()
		if q.Get("type") != "TXT" {
			cloudflareError(w, http.StatusBadRequest, 1004, "only TXT is faked")
			return
		}
		name := normalize(q.Get("name"))
		var result []map[string]string
		f.mu.Lock()
		for _, rec := range f.records {
			if rec.ZoneID == parts[1] && rec.Name == name {
				// The API returns TXT content quoted.
				result = append(result, map[string]string{"id": rec.ID, "type": "TXT", "name": rec.Name, "content": `"` + rec.Content + `"`})
			}
		}
		f.mu.Unlock()
		if result == nil {
			result = []map[string]string{}
		}
		cloudflareOK(w, result)
	case r.Method == http.MethodPost && len(parts) == 3 && parts[0] == "zones" && parts[2] == "dns_records":
		var body struct {
			Type, Name, Content string
			TTL                 int
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Type != "TXT" || body.Name == "" || body.Content == "" {
			cloudflareError(w, http.StatusBadRequest, 1004, "DNS Validation Error")
			return
		}
		if f.Records.ZoneOf(body.Name) == "" || zoneID(f.Records.ZoneOf(body.Name)) != parts[1] {
			cloudflareError(w, http.StatusBadRequest, 1004, "the record is not in this zone")
			return
		}
		f.mu.Lock()
		f.nextID++
		rec := cloudflareRecord{ID: fmt.Sprintf("rec-%d", f.nextID), ZoneID: parts[1], Name: normalize(body.Name), Content: unquote(body.Content)}
		f.records[rec.ID] = rec
		f.mu.Unlock()
		f.Records.AddTXT(rec.Name, rec.Content)
		cloudflareOK(w, map[string]string{"id": rec.ID, "type": "TXT", "name": rec.Name, "content": `"` + rec.Content + `"`})
	case r.Method == http.MethodDelete && len(parts) == 4 && parts[0] == "zones" && parts[2] == "dns_records":
		f.mu.Lock()
		rec, ok := f.records[parts[3]]
		delete(f.records, parts[3])
		f.mu.Unlock()
		if !ok || rec.ZoneID != parts[1] {
			cloudflareError(w, http.StatusNotFound, 81044, "Record does not exist.")
			return
		}
		f.Records.RemoveTXT(rec.Name, rec.Content)
		cloudflareOK(w, map[string]string{"id": rec.ID})
	default:
		cloudflareError(w, http.StatusNotFound, 7000, "No route for that URI")
	}
}

func zoneID(name string) string { return "zone-" + normalize(name) }

func cloudflareOK(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": result})
}

func cloudflareError(w http.ResponseWriter, status, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": false, "result": nil,
		"errors": []map[string]any{{"code": code, "message": message}},
	})
}
