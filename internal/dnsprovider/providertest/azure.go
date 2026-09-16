package providertest

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// Azure fakes Azure's token endpoint and the Azure DNS resource manager
// API: zone listing in a resource group and TXT record sets, behind a
// client credentials grant.
type Azure struct {
	*httptest.Server
	Records *Records
	// TenantID, ClientID, SubscriptionID, and ResourceGroup are what the
	// fake expects, for the config under test.
	TenantID, ClientID, SubscriptionID, ResourceGroup string

	mu     sync.Mutex
	tokens map[string]bool
}

// AzureOptions configure an Azure fake.
type AzureOptions struct {
	TenantID, ClientID, SubscriptionID, ResourceGroup string
	// ClientSecret is the secret the token endpoint accepts.
	ClientSecret string
}

// NewAzure serves records over TLS. Its URL is both the authority and the
// resource manager endpoint. Close it when done.
func NewAzure(records *Records, opts AzureOptions) *Azure {
	f := &Azure{
		Records: records, tokens: map[string]bool{},
		TenantID: opts.TenantID, ClientID: opts.ClientID, SubscriptionID: opts.SubscriptionID, ResourceGroup: opts.ResourceGroup,
	}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+opts.TenantID+"/oauth2/v2.0/token" {
			f.token(w, r, opts.ClientSecret)
			return
		}
		if !f.authorized(r) {
			azureError(w, http.StatusUnauthorized, "InvalidAuthenticationToken", "The access token is invalid.")
			return
		}
		f.handle(w, r)
	}))
	return f
}

func (f *Azure) token(w http.ResponseWriter, r *http.Request, clientSecret string) {
	if r.Method != http.MethodPost || r.ParseForm() != nil {
		azureError(w, http.StatusBadRequest, "invalid_request", "POST a form")
		return
	}
	form := r.PostForm
	if form.Get("grant_type") != "client_credentials" || form.Get("client_id") != f.ClientID ||
		subtle.ConstantTimeCompare([]byte(form.Get("client_secret")), []byte(clientSecret)) != 1 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided."})
		return
	}
	if !strings.HasSuffix(form.Get("scope"), "/.default") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_scope", "error_description": "scope must end in /.default"})
		return
	}
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	token := "azure-" + hex.EncodeToString(raw[:])
	f.mu.Lock()
	f.tokens[token] = true
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer", "expires_in": 3599, "access_token": token})
}

func (f *Azure) authorized(r *http.Request) bool {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens[token]
}

func (f *Azure) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("api-version") == "" {
		azureError(w, http.StatusBadRequest, "MissingApiVersionParameter", "The api-version query parameter is required.")
		return
	}
	prefix := "/subscriptions/" + f.SubscriptionID + "/resourceGroups/" + f.ResourceGroup + "/providers/Microsoft.Network/dnsZones"
	rest, ok := strings.CutPrefix(r.URL.Path, prefix)
	if !ok {
		azureError(w, http.StatusNotFound, "ResourceGroupNotFound", "Resource group not found.")
		return
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	switch {
	case r.Method == http.MethodGet && rest == "":
		var value []map[string]string
		for _, z := range f.Records.Zones() {
			value = append(value, map[string]string{"name": z, "id": prefix + "/" + z})
		}
		if value == nil {
			value = []map[string]string{}
		}
		azureJSON(w, http.StatusOK, map[string]any{"value": value})
	case len(parts) == 3 && parts[1] == "TXT":
		zone, relative := normalize(parts[0]), strings.ToLower(parts[2])
		if !f.Records.HasZone(zone) {
			azureError(w, http.StatusNotFound, "ResourceNotFound", "The Resource 'Microsoft.Network/dnsZones/"+zone+"' was not found.")
			return
		}
		name := relative + "." + zone
		if relative == "@" {
			name = zone
		}
		switch r.Method {
		case http.MethodGet:
			values := f.Records.TXT(name)
			if len(values) == 0 {
				azureError(w, http.StatusNotFound, "NotFound", "The record set was not found.")
				return
			}
			azureJSON(w, http.StatusOK, azureRecordSet(relative, values))
		case http.MethodPut:
			var body struct {
				Properties struct {
					TTL        int `json:"TTL"`
					TXTRecords []struct {
						Value []string `json:"value"`
					} `json:"TXTRecords"`
				} `json:"properties"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Properties.TXTRecords) == 0 {
				azureError(w, http.StatusBadRequest, "BadRequest", "a TXT record set needs records")
				return
			}
			var values []string
			for _, rec := range body.Properties.TXTRecords {
				values = append(values, strings.Join(rec.Value, ""))
			}
			f.Records.SetTXT(name, values)
			azureJSON(w, http.StatusOK, azureRecordSet(relative, values))
		case http.MethodDelete:
			if len(f.Records.TXT(name)) == 0 {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			f.Records.SetTXT(name, nil)
			w.WriteHeader(http.StatusOK)
		default:
			azureError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", r.Method)
		}
	default:
		azureError(w, http.StatusNotFound, "ResourceNotFound", "unknown path")
	}
}

func azureRecordSet(relative string, values []string) map[string]any {
	records := make([]map[string][]string, len(values))
	for i, v := range values {
		records[i] = map[string][]string{"value": {v}}
	}
	return map[string]any{"name": relative, "type": "Microsoft.Network/dnsZones/TXT", "properties": map[string]any{"TTL": 60, "TXTRecords": records}}
}

func azureJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func azureError(w http.ResponseWriter, status int, code, message string) {
	azureJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
