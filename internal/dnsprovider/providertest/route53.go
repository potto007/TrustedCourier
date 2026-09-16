package providertest

import (
	"crypto/subtle"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/potto007/TrustedCourier/internal/dnsprovider/sigv4"
)

// Route53 fakes the Route 53 API: hosted zone lookup by name, record set
// listing, and change batches, behind SigV4-signed requests.
type Route53 struct {
	*httptest.Server
	Records *Records
}

// NewRoute53 serves records over TLS, accepting requests signed with the
// access key and secret. Close it when done.
func NewRoute53(records *Records, accessKeyID string, secretAccessKey []byte) *Route53 {
	f := &Route53{Records: records}
	secret := slices.Clone(secretAccessKey)
	f.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := verifySigV4(r, body, accessKeyID, secret); err != "" {
			route53Error(w, http.StatusForbidden, "SignatureDoesNotMatch", err)
			return
		}
		f.handle(w, r, body)
	}))
	return f
}

var credentialPattern = regexp.MustCompile(`Credential=([^/]+)/(\d{8})/([^/]+)/([^/]+)/aws4_request, SignedHeaders=([^,]+), Signature=`)

// verifySigV4 re-signs r as the client should have and compares. It
// returns why the signature is wrong, or empty.
func verifySigV4(r *http.Request, body []byte, accessKeyID string, secret []byte) string {
	auth := r.Header.Get("Authorization")
	m := credentialPattern.FindStringSubmatch(auth)
	if m == nil {
		return "no SigV4 Authorization header"
	}
	if m[1] != accessKeyID {
		return "unknown access key id"
	}
	if m[3] != "us-east-1" || m[4] != "route53" {
		return "wrong credential scope " + m[3] + "/" + m[4]
	}
	at, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		return "no X-Amz-Date"
	}
	if d := time.Since(at); d > 5*time.Minute || d < -5*time.Minute {
		return "request time too skewed"
	}
	again, err := http.NewRequest(r.Method, "https://"+r.Host+r.URL.RequestURI(), nil)
	if err != nil {
		return err.Error()
	}
	for _, name := range strings.Split(m[5], ";") {
		if name == "host" || name == "x-amz-date" {
			continue
		}
		again.Header[http.CanonicalHeaderKey(name)] = r.Header.Values(name)
	}
	sigv4.Sign(again, body, accessKeyID, secret, "us-east-1", "route53", at)
	if subtle.ConstantTimeCompare([]byte(again.Header.Get("Authorization")), []byte(auth)) != 1 {
		return "the signature does not match"
	}
	return ""
}

type route53RecordSet struct {
	Name            string   `xml:"Name"`
	Type            string   `xml:"Type"`
	TTL             int      `xml:"TTL"`
	ResourceRecords []string `xml:"ResourceRecords>ResourceRecord>Value"`
}

func (f *Route53) handle(w http.ResponseWriter, r *http.Request, body []byte) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "2013-04-01" {
		route53Error(w, http.StatusNotFound, "NoSuchAction", "unknown path")
		return
	}
	switch {
	case r.Method == http.MethodGet && parts[1] == "hostedzonesbyname" && len(parts) == 2:
		// Zones are listed from the first whose name is at or after dnsname.
		dnsname := normalize(r.URL.Query().Get("dnsname"))
		max, _ := strconv.Atoi(r.URL.Query().Get("maxitems"))
		if max <= 0 {
			max = 100
		}
		var b strings.Builder
		b.WriteString(`<ListHostedZonesByNameResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><HostedZones>`)
		n := 0
		for _, z := range f.Records.Zones() {
			if z+"." < dnsname+"." || n >= max {
				continue
			}
			n++
			b.WriteString("<HostedZone><Id>/hostedzone/" + route53ZoneID(z) + "</Id><Name>" + z + ".</Name><Config><PrivateZone>false</PrivateZone></Config></HostedZone>")
		}
		b.WriteString("</HostedZones><IsTruncated>false</IsTruncated><MaxItems>" + strconv.Itoa(max) + "</MaxItems></ListHostedZonesByNameResponse>")
		route53XML(w, http.StatusOK, b.String())
	case r.Method == http.MethodGet && parts[1] == "hostedzone" && len(parts) == 4 && parts[3] == "rrset":
		zone := f.zoneByID(parts[2])
		if zone == "" {
			route53Error(w, http.StatusNotFound, "NoSuchHostedZone", "no hosted zone "+parts[2])
			return
		}
		name := normalize(r.URL.Query().Get("name"))
		var b strings.Builder
		b.WriteString(`<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceRecordSets>`)
		if values := f.Records.TXT(name); len(values) > 0 && f.Records.ZoneOf(name) == zone && r.URL.Query().Get("type") == "TXT" {
			b.WriteString("<ResourceRecordSet><Name>" + name + ".</Name><Type>TXT</Type><TTL>60</TTL><ResourceRecords>")
			for _, v := range values {
				b.WriteString("<ResourceRecord><Value>&quot;" + v + "&quot;</Value></ResourceRecord>")
			}
			b.WriteString("</ResourceRecords></ResourceRecordSet>")
		}
		b.WriteString("</ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>1</MaxItems></ListResourceRecordSetsResponse>")
		route53XML(w, http.StatusOK, b.String())
	case r.Method == http.MethodPost && parts[1] == "hostedzone" && len(parts) == 4 && parts[3] == "rrset":
		zone := f.zoneByID(parts[2])
		if zone == "" {
			route53Error(w, http.StatusNotFound, "NoSuchHostedZone", "no hosted zone "+parts[2])
			return
		}
		var req struct {
			Changes []struct {
				Action string           `xml:"Action"`
				Set    route53RecordSet `xml:"ResourceRecordSet"`
			} `xml:"ChangeBatch>Changes>Change"`
		}
		if err := xml.Unmarshal(body, &req); err != nil || len(req.Changes) == 0 {
			route53Error(w, http.StatusBadRequest, "InvalidInput", "malformed change batch")
			return
		}
		for _, c := range req.Changes {
			name := normalize(c.Set.Name)
			if c.Set.Type != "TXT" || f.Records.ZoneOf(name) != zone {
				route53Error(w, http.StatusBadRequest, "InvalidChangeBatch", "RRSet with DNS name "+c.Set.Name+" is not permitted in zone "+zone)
				return
			}
			values := make([]string, len(c.Set.ResourceRecords))
			for i, v := range c.Set.ResourceRecords {
				values[i] = unquote(v)
			}
			switch c.Action {
			case "UPSERT":
				f.Records.SetTXT(name, values)
			case "DELETE":
				current := f.Records.TXT(name)
				slices.Sort(current)
				slices.Sort(values)
				if !slices.Equal(current, values) {
					route53Error(w, http.StatusBadRequest, "InvalidChangeBatch", "Tried to delete resource record set ["+c.Set.Name+"] but the values provided do not match the current values")
					return
				}
				f.Records.SetTXT(name, nil)
			default:
				route53Error(w, http.StatusBadRequest, "InvalidInput", "unknown action "+c.Action)
				return
			}
		}
		route53XML(w, http.StatusOK, `<ChangeResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ChangeInfo><Id>/change/C1</Id><Status>PENDING</Status><SubmittedAt>`+time.Now().UTC().Format(time.RFC3339)+`</SubmittedAt></ChangeInfo></ChangeResourceRecordSetsResponse>`)
	default:
		route53Error(w, http.StatusNotFound, "NoSuchAction", "unknown path")
	}
}

func route53ZoneID(zone string) string {
	return "Z" + strings.ToUpper(strings.NewReplacer(".", "", "-", "").Replace(zone))
}

func (f *Route53) zoneByID(id string) string {
	for _, z := range f.Records.Zones() {
		if route53ZoneID(z) == id {
			return z
		}
	}
	return ""
}

func route53XML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, xml.Header+body)
}

func route53Error(w http.ResponseWriter, status int, code, message string) {
	route53XML(w, status, `<ErrorResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><Error><Type>Sender</Type><Code>`+code+`</Code><Message>`+message+`</Message></Error><RequestId>req-1</RequestId></ErrorResponse>`)
}
