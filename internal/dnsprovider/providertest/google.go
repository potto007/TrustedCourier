package providertest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
)

// Google fakes Google's OAuth 2.0 token endpoint for service accounts and
// the Cloud DNS API: managed zone lookup by DNS name, record set listing,
// and changes, behind a signed JWT assertion.
type Google struct {
	*httptest.Server
	Records *Records
	// Project is the project the fake serves.
	Project string

	key    *rsa.PrivateKey
	email  string
	mu     sync.Mutex
	tokens map[string]bool
}

// NewGoogle serves records for project over TLS. Close it when done.
func NewGoogle(records *Records, project string) *Google {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	f := &Google{Records: records, Project: project, key: key, email: "courier@" + project + ".iam.gserviceaccount.com", tokens: map[string]bool{}}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			f.token(w, r)
			return
		}
		if !f.authorized(r) {
			googleError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Request had invalid authentication credentials.")
			return
		}
		f.handle(w, r)
	}))
	return f
}

// ServiceAccountKey returns a service account key file, as Google hands
// one out, whose token_uri is the fake's.
func (f *Google) ServiceAccountKey() []byte {
	der, err := x509.MarshalPKCS8PrivateKey(f.key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	data, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     f.Project,
		"private_key_id": "key-1",
		"private_key":    string(keyPEM),
		"client_email":   f.email,
		"client_id":      "1234567890",
		"token_uri":      f.URL + "/token",
	})
	if err != nil {
		panic(err)
	}
	return data
}

func (f *Google) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.ParseForm() != nil || r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		googleOAuthError(w, "invalid_request", "POST a jwt-bearer grant")
		return
	}
	parts := strings.Split(r.PostForm.Get("assertion"), ".")
	if len(parts) != 3 {
		googleOAuthError(w, "invalid_grant", "malformed assertion")
		return
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		googleOAuthError(w, "invalid_grant", "malformed signature")
		return
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&f.key.PublicKey, crypto.SHA256, digest[:], signature) != nil {
		googleOAuthError(w, "invalid_grant", "Invalid JWT Signature.")
		return
	}
	var header struct{ Alg, Typ string }
	var claims struct{ Iss, Scope, Aud string }
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	c, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if json.Unmarshal(h, &header) != nil || json.Unmarshal(c, &claims) != nil || header.Alg != "RS256" ||
		claims.Iss != f.email || claims.Aud != f.URL+"/token" || !strings.Contains(claims.Scope, "ndev.clouddns.readwrite") {
		googleOAuthError(w, "invalid_grant", "Invalid JWT: claims")
		return
	}
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	token := "ya29." + hex.EncodeToString(raw[:])
	f.mu.Lock()
	f.tokens[token] = true
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "expires_in": 3599, "token_type": "Bearer"})
}

func (f *Google) authorized(r *http.Request) bool {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens[token]
}

type googleRRSet struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	RRDatas []string `json:"rrdatas"`
}

func (f *Google) handle(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, "/dns/v1/projects/"+f.Project+"/managedZones")
	if !ok {
		googleError(w, http.StatusForbidden, "PERMISSION_DENIED", "unknown project or path")
		return
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	switch {
	case r.Method == http.MethodGet && rest == "":
		zones := []map[string]string{}
		for _, z := range f.Records.Zones() {
			if want := r.URL.Query().Get("dnsName"); want == "" || normalize(want) == z {
				zones = append(zones, map[string]string{"name": googleZoneName(z), "dnsName": z + ".", "visibility": "public"})
			}
		}
		googleJSON(w, http.StatusOK, map[string]any{"managedZones": zones})
	case len(parts) == 2 && parts[1] == "rrsets" && r.Method == http.MethodGet:
		zone := f.zoneByName(parts[0])
		if zone == "" {
			googleError(w, http.StatusNotFound, "NOT_FOUND", "The 'parameters.managedZone' resource named '"+parts[0]+"' does not exist.")
			return
		}
		name := normalize(r.URL.Query().Get("name"))
		rrsets := []googleRRSet{}
		if values := f.Records.TXT(name); len(values) > 0 && f.Records.ZoneOf(name) == zone && r.URL.Query().Get("type") == "TXT" {
			rrsets = append(rrsets, googleRRSetOf(name, values))
		}
		googleJSON(w, http.StatusOK, map[string]any{"rrsets": rrsets})
	case len(parts) == 2 && parts[1] == "changes" && r.Method == http.MethodPost:
		zone := f.zoneByName(parts[0])
		if zone == "" {
			googleError(w, http.StatusNotFound, "NOT_FOUND", "The 'parameters.managedZone' resource named '"+parts[0]+"' does not exist.")
			return
		}
		var change struct {
			Additions, Deletions []googleRRSet
		}
		if err := json.NewDecoder(r.Body).Decode(&change); err != nil {
			googleError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "malformed change")
			return
		}
		for _, d := range change.Deletions {
			name := normalize(d.Name)
			current := f.Records.TXT(name)
			values := unquoteAll(d.RRDatas)
			slices.Sort(current)
			slices.Sort(values)
			// A deletion must match the set exactly, TTL included.
			if d.Type != "TXT" || d.TTL != 60 || len(current) == 0 || !slices.Equal(current, values) {
				googleError(w, http.StatusNotFound, "NOT_FOUND", "The resource 'entity.change.deletions["+d.Name+"][TXT]' does not match.")
				return
			}
		}
		for _, a := range change.Additions {
			name := normalize(a.Name)
			if a.Type != "TXT" || f.Records.ZoneOf(name) != zone || len(a.RRDatas) == 0 {
				googleError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "the addition is not in this zone")
				return
			}
			if deleted := slices.IndexFunc(change.Deletions, func(d googleRRSet) bool { return normalize(d.Name) == name }); deleted < 0 && len(f.Records.TXT(name)) > 0 {
				googleError(w, http.StatusConflict, "ALREADY_EXISTS", "The resource 'entity.change.additions["+a.Name+"][TXT]' already exists.")
				return
			}
		}
		for _, d := range change.Deletions {
			f.Records.SetTXT(normalize(d.Name), nil)
		}
		for _, a := range change.Additions {
			f.Records.SetTXT(normalize(a.Name), unquoteAll(a.RRDatas))
		}
		googleJSON(w, http.StatusOK, map[string]any{"kind": "dns#change", "id": "1", "status": "pending", "additions": change.Additions, "deletions": change.Deletions})
	default:
		googleError(w, http.StatusNotFound, "NOT_FOUND", "unknown path")
	}
}

func googleZoneName(zone string) string {
	return "zone-" + strings.ReplaceAll(zone, ".", "-")
}

func (f *Google) zoneByName(name string) string {
	for _, z := range f.Records.Zones() {
		if googleZoneName(z) == name {
			return z
		}
	}
	return ""
}

func googleRRSetOf(name string, values []string) googleRRSet {
	set := googleRRSet{Name: name + ".", Type: "TXT", TTL: 60}
	for _, v := range values {
		set.RRDatas = append(set.RRDatas, `"`+v+`"`)
	}
	return set
}

func unquoteAll(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = unquote(v)
	}
	return out
}

func googleJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func googleError(w http.ResponseWriter, status int, code, message string) {
	googleJSON(w, status, map[string]any{"error": map[string]any{"code": status, "message": message, "status": code}})
}

func googleOAuthError(w http.ResponseWriter, code, description string) {
	googleJSON(w, http.StatusBadRequest, map[string]string{"error": code, "error_description": description})
}
