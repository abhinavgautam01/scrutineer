package web

import (
	"bytes"
	"strings"
	"testing"
)

func TestLocationURL(t *testing.T) {
	cases := []struct {
		repoID      uint
		commit, loc string
		want        string
	}{
		{5, "abc123", "lib/x.rb:10", "/repositories/5/blob/abc123/lib/x.rb?line=10#L10"},
		{5, "abc123", "lib/x.rb:10-20", "/repositories/5/blob/abc123/lib/x.rb?line=10-20#L10"},
		{5, "abc123", "lib/x.rb", "/repositories/5/blob/abc123/lib/x.rb"},
		{5, "abc123", "./z.c:1", "/repositories/5/blob/abc123/z.c?line=1#L1"},
		{5, "abc123", "src/with space.go:3", "/repositories/5/blob/abc123/src/with%20space.go?line=3#L3"},
		{0, "abc", "x:1", ""},
		{5, "", "x:1", ""},
		{5, "abc", "", ""},
	}
	for _, c := range cases {
		if got := locationURL(c.repoID, c.commit, c.loc); got != c.want {
			t.Errorf("locationURL(%d,%q,%q) = %q, want %q", c.repoID, c.commit, c.loc, got, c.want)
		}
	}
}

func TestTemplateLocationURL(t *testing.T) {
	want := "/repositories/5/blob/abc/x.go?line=1#L1"
	for _, id := range []any{uint(5), 5, uint64(5)} {
		got, err := templateLocationURL(id, "abc", "x.go:1")
		if err != nil || got != want {
			t.Errorf("templateLocationURL(%T) = %q, %v; want %q", id, got, err, want)
		}
	}
	if got, err := templateLocationURL(uint(0), "abc", "x.go:1"); err != nil || got != "" {
		t.Errorf("repoID 0 = %q, %v; want empty and no error", got, err)
	}
	for _, id := range []any{nil, "5", -1, int64(5)} {
		if got, err := templateLocationURL(id, "abc", "x.go:1"); err == nil {
			t.Errorf("templateLocationURL(%#v) = %q, want an error", id, got)
		}
	}
}

func TestLocLinkFailsWithoutRepoID(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	var buf bytes.Buffer
	ok := map[string]any{"RepoID": uint(5), "Commit": "abc", "Location": "x.go:1"}
	if err := s.tmpl.ExecuteTemplate(&buf, "loc-link", ok); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `href="/repositories/5/blob/abc/x.go?line=1#L1"`) {
		t.Errorf("loc-link did not link: %s", buf.String())
	}
	buf.Reset()
	wrongKey := map[string]any{"HTMLURL": "https://example.com/r", "Commit": "abc", "Location": "x.go:1"}
	if err := s.tmpl.ExecuteTemplate(&buf, "loc-link", wrongKey); err == nil || !strings.Contains(err.Error(), "locurl") {
		t.Errorf("loc-link without RepoID: err = %v, want a locurl error", err)
	}
}
