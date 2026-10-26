package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
)

func TestRepoBlob_highlightScriptBounds(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to run the code browser script")
	}
	s, done := newTestServer(t)
	defer done()
	src := filepath.Join(t.TempDir(), "repo")
	commit, _ := seedGitRepo(t, src)
	repo := db.Repository{URL: "file://" + src, Name: "highlight"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	pages := []struct {
		Query       string
		Highlighted []int
		Scrolled    []int
		HTML        string
	}{
		{Query: "2", Highlighted: []int{2}, Scrolled: []int{2}},
		{Query: "2-3", Highlighted: []int{2, 3}, Scrolled: []int{2}},
		{Query: "2-9007199254740992", Highlighted: []int{2, 3, 4}, Scrolled: []int{2}},
		{Query: "9007199254740992", Highlighted: []int{}, Scrolled: []int{}},
		{Query: "9007199254740992-9007199254740993", Highlighted: []int{}, Scrolled: []int{}},
		{Query: "5", Highlighted: []int{}, Scrolled: []int{}},
		{Query: "", Highlighted: []int{}, Scrolled: []int{}},
	}
	for i := range pages {
		w := httptest.NewRecorder()
		path := fmt.Sprintf("/repositories/%d/blob/%s/hello.go?line=%s", repo.ID, commit, pages[i].Query)
		s.Handler().ServeHTTP(w, localReq("GET", path))
		if w.Code != 200 {
			t.Fatalf("%s: status %d: %s", path, w.Code, w.Body)
		}
		pages[i].HTML = w.Body.String()
	}
	input, err := json.Marshal(pages)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), node, "testdata/code_browser.cjs")
	cmd.Stdin = bytes.NewReader(input)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("code browser script: %v\n%s", err, out)
	}
}
