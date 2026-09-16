package sigv4

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// The worked example in AWS's "Signature Version 4 signing process"
// documentation: a GET to IAM with a fixed date and the documented example
// credentials.
func TestSignMatchesTheAWSExample(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	now := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	Sign(req, nil, "AKIDEXAMPLE", []byte("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"), "us-east-1", "iam", now)

	if got := req.Header.Get("X-Amz-Date"); got != "20150830T123600Z" {
		t.Errorf("X-Amz-Date = %q", got)
	}
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization =\n%s\nwant\n%s", got, want)
	}
}

func TestSignCoversTheBodyAndSortsTheQuery(t *testing.T) {
	body := []byte("<ChangeResourceRecordSetsRequest/>")
	req, err := http.NewRequest(http.MethodPost, "https://route53.amazonaws.com/2013-04-01/hostedzone/Z1/rrset?maxitems=1&name=_acme-challenge.example.com.&type=TXT", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	Sign(req, body, "AKIDEXAMPLE", []byte("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"), "us-east-1", "route53", time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC))
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "Credential=AKIDEXAMPLE/20260915/us-east-1/route53/aws4_request") {
		t.Errorf("Authorization = %q", auth)
	}
	if !strings.Contains(auth, "SignedHeaders=host;x-amz-date,") {
		t.Errorf("Authorization = %q", auth)
	}
	// The same request with the query in another order signs the same.
	again, _ := http.NewRequest(http.MethodPost, "https://route53.amazonaws.com/2013-04-01/hostedzone/Z1/rrset?type=TXT&name=_acme-challenge.example.com.&maxitems=1", strings.NewReader(string(body)))
	Sign(again, body, "AKIDEXAMPLE", []byte("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"), "us-east-1", "route53", time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC))
	if again.Header.Get("Authorization") != auth {
		t.Errorf("query order changes the signature:\n%s\n%s", auth, again.Header.Get("Authorization"))
	}
	// A different body signs differently.
	other, _ := http.NewRequest(http.MethodPost, req.URL.String(), strings.NewReader("x"))
	Sign(other, []byte("x"), "AKIDEXAMPLE", []byte("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"), "us-east-1", "route53", time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC))
	if other.Header.Get("Authorization") == auth {
		t.Error("the body is not signed")
	}
}
