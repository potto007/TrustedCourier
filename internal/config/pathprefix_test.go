package config

import "testing"

func TestPathPrefixMatchesWholeDecodedSegments(t *testing.T) {
	prefix, err := ParsePathPrefix("/repos/o/r")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path string
		want bool
	}{
		{"/repos/o/r", true},
		{"/repos/o/r/", true},
		{"/repos/o/r/issues", true},
		{"/repos/o/r/issues/1/comments", true},
		// Percent-encoded letters are the same path to the Upstream.
		{"/%72epos/o/%72/issues", true},
		// An encoded slash in the part after the prefix stays under it.
		{"/repos/o/r/issues%2F1", true},
		{"/repos/o/rx", false},
		{"/repos/o", false},
		{"", false},
		{"/", false},
		{"/REPOS/o/r", false},
		// An encoded slash could make the Upstream see other segments.
		{"/repos%2Fo/r/issues", false},
		{"/repos/o/r%2Fissues", false},
		{"/repos//o/r", false},
		{"//repos/o/r", false},
		{"/repos;x/o/r", false},
		{`/repos\o/r`, false},
		// Dot segments, however written, could climb out of the prefix.
		{"/repos/o/r/../../x", false},
		{"/repos/o/r/%2e%2e/%2E%2e/x", false},
		{"/repos/o/r/x%2F..%2F..%2Fy", false},
		{"/repos/o/r/..;/x", false},
		{`/repos/o/r/x%5C..%5C..%5Cy`, false},
		// Overlong UTF-8 for "..", which old servers decode.
		{"/repos/o/r/%c0%ae%c0%ae/x", false},
		{"/repos/o/r/%zz", false},
	}
	for _, c := range cases {
		if got := prefix.Matches(c.path); got != c.want {
			t.Errorf("%q matches %q = %v, want %v", prefix, c.path, got, c.want)
		}
	}
}

func TestRootPathPrefixMatchesEveryPath(t *testing.T) {
	prefix, err := ParsePathPrefix("/")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", "/", "/v1/models", "/%72epos"} {
		if !prefix.Matches(path) {
			t.Errorf("%q does not match %q", prefix, path)
		}
	}
	if prefix.Matches("/v1/../x") {
		t.Error(`"/" matches a path with a dot segment`)
	}
}

func TestPathPrefixTrailingSlashIsIgnored(t *testing.T) {
	prefix, err := ParsePathPrefix("/repos/o/r/")
	if err != nil {
		t.Fatal(err)
	}
	if got := prefix.String(); got != "/repos/o/r" {
		t.Errorf("String() = %q, want /repos/o/r", got)
	}
	if !prefix.Matches("/repos/o/r") || prefix.Matches("/repos/o/rx") {
		t.Errorf("%q does not match by whole segments", prefix)
	}
}

func TestInvalidPathPrefixesAreRefused(t *testing.T) {
	for _, s := range []string{
		"", "repos", "/repos/../x", "/repos/./x", "/repos/%2e%2e", "/repos//x",
		"/a?b", "/a#b", "/a%2Fb", "/a%5Cb", `/a\b`, "/a%zz", "/a;b", "/a%00", "/a b",
		"/%c0%ae",
	} {
		if _, err := ParsePathPrefix(s); err == nil {
			t.Errorf("ParsePathPrefix(%q) succeeded", s)
		}
	}
}
