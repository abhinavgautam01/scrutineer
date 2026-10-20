package web

import (
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"scrutineer/internal/db"
)

// pageBody renders path through the full handler stack and returns the body.
func pageBody(t *testing.T, s *Server, path string) string {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, path))
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s status %d: %s", path, w.Code, w.Body)
	}
	return w.Body.String()
}

func TestPageTitle_defaultsToSectionName(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	for path, want := range map[string]string{
		"/findings": "Findings",
		"/settings": "Settings",
		"/":         "Repositories",
	} {
		body := pageBody(t, s, path)
		if !strings.Contains(body, "<title>"+want+" · scrutineer</title>") {
			t.Errorf("%s: missing title %q in %s", path, want, body[:min(len(body), 600)])
		}
	}
}

func TestPageTitle_detailPagesNameTheirSubject(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/titled", Name: "titled"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "Heap overflow in parser", Severity: "High", Status: db.FindingReady}
	s.DB.Create(&f)

	for path, want := range map[string]string{
		fmt.Sprintf("/repositories/%d", repo.ID): "<title>titled · scrutineer</title>",
		fmt.Sprintf("/findings/%d", f.ID):        "<title>Heap overflow in parser · titled · scrutineer</title>",
		fmt.Sprintf("/scans/%d", scan.ID):        fmt.Sprintf("<title>Scan #%d · %s · titled · scrutineer</title>", scan.ID, deepDiveSkillName),
	} {
		if body := pageBody(t, s, path); !strings.Contains(body, want) {
			t.Errorf("%s: missing %q", path, want)
		}
	}
}

func TestLayout_rendersSidebarToggle(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	body := pageBody(t, s, "/")
	for _, want := range []string{`id="sidebar"`, `data-sidebar-toggle`, `aria-controls="sidebar"`, `aria-expanded="false"`} {
		if !strings.Contains(body, want) {
			t.Errorf("layout missing %s", want)
		}
	}
}

func attr(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

func walk(n *html.Node, visit func(*html.Node)) {
	visit(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c, visit)
	}
}

func TestLayout_dialogsAreNamed(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	doc, err := html.Parse(strings.NewReader(pageBody(t, s, "/")))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	var dialogs []*html.Node
	walk(doc, func(n *html.Node) {
		if n.Type != html.ElementNode {
			return
		}
		if id, ok := attr(n, "id"); ok {
			ids[id] = true
		}
		if n.Data == "dialog" {
			dialogs = append(dialogs, n)
		}
	})
	if len(dialogs) == 0 {
		t.Fatal("no dialogs rendered")
	}
	for _, d := range dialogs {
		id, _ := attr(d, "id")
		for _, key := range []string{"aria-labelledby", "aria-describedby"} {
			target, ok := attr(d, key)
			if key == "aria-labelledby" && !ok {
				t.Errorf("dialog #%s has no aria-labelledby", id)
			}
			if ok && !ids[target] {
				t.Errorf("dialog #%s %s points at missing id %q", id, key, target)
			}
		}
	}
}

func TestLayout_addRepoFieldsAreLabelled(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	body := pageBody(t, s, "/")
	for _, want := range []string{`for="add-repo-url"`, `id="add-repo-url"`, `for="bulk-add-repo-urls"`, `for="org-add-repo-org"`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	if !regexp.MustCompile(`<label[^>]*for="add-repo-url"`).MatchString(body) {
		t.Error("no <label> targets add-repo-url")
	}
}

func TestSettings_exposesSelectionAndLabels(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	body := pageBody(t, s, "/settings")
	if got := strings.Count(body, `aria-pressed="true"`); got != 3 {
		t.Errorf("aria-pressed=true count = %d, want 3 (theme, color scheme, effort)", got)
	}
	if !regexp.MustCompile(`<label[^>]*for="scan_schedule_cron"`).MatchString(body) {
		t.Error("cron input has no associated label")
	}
	if !strings.Contains(body, `id="scan_schedule_cron"`) {
		t.Error("cron input has no id")
	}
}

type contrastPair struct{ fg, bg string }

var contrastPairs = []contrastPair{
	{"foreground", "background"}, {"foreground", "card"},
	{"card-foreground", "card"},
	{"popover-foreground", "popover"},
	{"muted-foreground", "background"}, {"muted-foreground", "card"},
	{"muted-foreground", "muted"}, {"muted-foreground", "popover"},
	{"primary-foreground", "primary"},
	{"secondary-foreground", "secondary"},
	{"accent-foreground", "accent"},
	{"destructive-foreground", "destructive"},
	{"destructive", "background"}, {"destructive", "card"},
	{"primary", "background"},
	{"sidebar-foreground", "sidebar"},
	{"sidebar-primary-foreground", "sidebar-primary"},
	{"sidebar-accent-foreground", "sidebar-accent"},
}

const minContrast = 4.5

var (
	cssComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	cssBlock   = regexp.MustCompile(`([^{}]+)\{([^{}]*)\}`)
	cssOklch   = regexp.MustCompile(`--([a-z-]+):\s*oklch\(([^)]*)\)`)
)

// parseOklch reads "L C H" (an optional percent on L and a trailing alpha are
// tolerated) and returns the three components.
func parseOklch(t *testing.T, raw string) (l, c, h float64) {
	t.Helper()
	raw, _, _ = strings.Cut(raw, "/")
	fields := strings.Fields(raw)
	if len(fields) != 3 {
		t.Fatalf("unexpected oklch components %q", raw)
	}
	vals := make([]float64, 3)
	for i, f := range fields {
		pct := strings.HasSuffix(f, "%")
		v, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSuffix(f, "%"), "deg"), 64)
		if err != nil {
			t.Fatalf("bad oklch component %q: %v", f, err)
		}
		if pct && i == 0 {
			v /= 100
		}
		vals[i] = v
	}
	return vals[0], vals[1], vals[2]
}

// relativeLuminance converts oklch to linear sRGB with the standard OKLab
// matrices and weights the clamped channels per WCAG 2.
func relativeLuminance(l, c, h float64) float64 {
	a := c * math.Cos(h*math.Pi/180)
	b := c * math.Sin(h*math.Pi/180)
	cube := func(v float64) float64 { return v * v * v }
	l_ := cube(l + 0.3963377774*a + 0.2158037573*b)
	m_ := cube(l - 0.1055613458*a - 0.0638541728*b)
	s_ := cube(l - 0.0894841775*a - 1.2914855480*b)
	clamp := func(v float64) float64 { return math.Min(1, math.Max(0, v)) }
	r := clamp(4.0767416621*l_ - 3.3077115913*m_ + 0.2309699292*s_)
	g := clamp(-1.2684380046*l_ + 2.6097574011*m_ - 0.3413193965*s_)
	bl := clamp(-0.0041960863*l_ - 0.7034186147*m_ + 1.7076147010*s_)
	return 0.2126*r + 0.7152*g + 0.0722*bl
}

func contrastRatio(a, b float64) float64 {
	if a < b {
		a, b = b, a
	}
	return (a + 0.05) / (b + 0.05)
}

func TestThemePalette_meetsContrast(t *testing.T) {
	raw, err := os.ReadFile("static/theme.css")
	if err != nil {
		t.Fatal(err)
	}
	css := cssComment.ReplaceAllString(string(raw), "")

	checked := 0
	for _, block := range cssBlock.FindAllStringSubmatch(css, -1) {
		selector := strings.Join(strings.Fields(block[1]), " ")
		lum := map[string]float64{}
		for _, m := range cssOklch.FindAllStringSubmatch(block[2], -1) {
			l, c, h := parseOklch(t, m[2])
			lum[m[1]] = relativeLuminance(l, c, h)
		}
		if _, ok := lum["background"]; !ok {
			continue
		}
		for _, p := range contrastPairs {
			fg, okFg := lum[p.fg]
			bg, okBg := lum[p.bg]
			if !okFg || !okBg {
				continue
			}
			checked++
			if ratio := contrastRatio(fg, bg); ratio < minContrast {
				t.Errorf("%s: %s on %s contrast %.2f, want >= %.1f", selector, p.fg, p.bg, ratio, minContrast)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no colour pairs were checked; the theme.css parser found nothing")
	}
}
