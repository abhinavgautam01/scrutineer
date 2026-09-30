package worker

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseEgressGrants_valid(t *testing.T) {
	got, err := ParseEgressGrants([]string{
		"API.Ecosyste.ms:443", "*.example.com:8443", "*.example.com:443", "api.ecosyste.ms:443", "a.example.net:9000", "a.example.net:80",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []EgressGrant{
		{Host: "*.example.com", Ports: []string{"443", "8443"}},
		{Host: "a.example.net", Ports: []string{"80", "9000"}},
		{Host: "api.ecosyste.ms", Ports: []string{"443"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseEgressGrants = %+v, want %+v", got, want)
	}
}

func TestParseEgressGrants_invalid(t *testing.T) {
	for _, entry := range []string{
		"", "api.ecosyste.ms", "https://api.ecosyste.ms:443", "api.ecosyste.ms:443/x", "u@api.ecosyste.ms:443",
		"10.0.0.1:443", "127.1:443", "[::1]:443", "::1:443", "localhost:443", "x.localhost:443",
		"host.docker.internal:8080", "Host.Docker.Internal:8080", "a.example.com:0", "a.example.com:65536",
		"a.example.com:http", "a.example.com:0443", "bad_host.example.com:443", " a.example.com:443",
	} {
		if _, err := ParseEgressGrants([]string{entry}); err == nil {
			t.Errorf("ParseEgressGrants(%q) accepted an invalid entry", entry)
		}
	}
}

func TestEgressGrantsEnvRoundTrip(t *testing.T) {
	grants, err := ParseEgressGrants([]string{"api.ecosyste.ms:443", "*.example.com:443", "*.example.com:8443"})
	if err != nil {
		t.Fatal(err)
	}
	s := FormatEgressGrants(grants)
	if want := "*.example.com:443|8443,api.ecosyste.ms:443"; s != want {
		t.Errorf("FormatEgressGrants = %q, want %q", s, want)
	}
	back, err := ParseEgressGrantsEnv(s)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, grants) {
		t.Errorf("round trip = %+v, want %+v", back, grants)
	}
	if got, err := ParseEgressGrantsEnv(""); err != nil || got != nil {
		t.Errorf("empty env = %v, %v, want nil", got, err)
	}
	for _, bad := range []string{"api.ecosyste.ms", "api.ecosyste.ms:", "10.0.0.1:443", "a.example.com:99999"} {
		if _, err := ParseEgressGrantsEnv(bad); err == nil {
			t.Errorf("ParseEgressGrantsEnv(%q) accepted bad input", bad)
		}
	}
}

func proxyAuth(token string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("scrutineer:"+token))
}

func TestEgressPortGuard(t *testing.T) {
	const token = "tok"
	grants, err := ParseEgressGrants([]string{"api.ecosyste.ms:443", "*.example.com:443", "*.example.com:8443", "plain.test:80"})
	if err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))
	reached := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached++; w.WriteHeader(http.StatusTeapot) })
	guard := egressPortGuard(token, []string{"*.anthropic.com"}, grants, log, next)

	connect := func(target string, auth bool) *http.Request {
		r := httptest.NewRequest(http.MethodConnect, "http://"+target, nil)
		r.Host = target
		if auth {
			r.Header.Set("Proxy-Authorization", proxyAuth(token))
		}
		return r
	}
	forward := func(rawURL string, auth bool) *http.Request {
		r := httptest.NewRequest(http.MethodGet, rawURL, nil)
		if auth {
			r.Header.Set("Proxy-Authorization", proxyAuth(token))
		}
		return r
	}
	relative := httptest.NewRequest(http.MethodGet, "/x", nil)
	relative.URL.Host = ""

	for _, tc := range []struct {
		name      string
		req       *http.Request
		wantCode  int
		wantReach bool
	}{
		{"base host any port", connect("api.anthropic.com:9999", true), http.StatusTeapot, true},
		{"granted host granted port", connect("api.ecosyste.ms:443", true), http.StatusTeapot, true},
		{"granted host default port", connect("api.ecosyste.ms", true), http.StatusTeapot, true},
		{"wildcard second port", connect("x.example.com:8443", true), http.StatusTeapot, true},
		{"granted host other port", connect("api.ecosyste.ms:8443", true), http.StatusForbidden, false},
		{"wildcard other port", connect("x.example.com:22", true), http.StatusForbidden, false},
		{"missing auth on denied port", connect("api.ecosyste.ms:22", false), http.StatusProxyAuthRequired, false},
		{"wrong auth on denied port", func() *http.Request {
			r := connect("api.ecosyste.ms:22", false)
			r.Header.Set("Proxy-Authorization", proxyAuth("wrong"))
			return r
		}(), http.StatusProxyAuthRequired, false},
		{"ungranted host falls through", connect("evil.test:22", true), http.StatusTeapot, true},
		{"forward without port is checked as 443", forward("http://api.ecosyste.ms/x", true), http.StatusTeapot, true},
		{"forward without port on an 80-only grant denied", forward("http://plain.test/x", true), http.StatusForbidden, false},
		{"forward explicit 80 on an 80-only grant allowed", forward("http://plain.test:80/x", true), http.StatusTeapot, true},
		{"forward explicit granted port", forward("http://x.example.com:8443/x", true), http.StatusTeapot, true},
		{"relative request falls through", relative, http.StatusTeapot, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := reached
			rec := httptest.NewRecorder()
			guard.ServeHTTP(rec, tc.req)
			if rec.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantCode)
			}
			if got := reached > before; got != tc.wantReach {
				t.Errorf("reached next = %v, want %v", got, tc.wantReach)
			}
			if tc.wantCode == http.StatusProxyAuthRequired && rec.Header().Get("Proxy-Authenticate") == "" {
				t.Error("407 lacks Proxy-Authenticate")
			}
		})
	}
	logged := logBuf.String()
	if !strings.Contains(logged, "port not granted by egress policy") || !strings.Contains(logged, "port=8443") {
		t.Errorf("denial not logged as expected: %q", logged)
	}
}

// connectStatus sends an authenticated CONNECT to a proxy and returns the
// status code it answers with.
func connectStatus(t *testing.T, proxyAddr, target, token string) int {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\nProxy-Authorization: " + proxyAuth(token) + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestStartScopedEgressProxyWithGrants_listener(t *testing.T) {
	grants, err := ParseEgressGrants([]string{"granted.example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	p := &EgressProxy{Allow: []string{"base.example.com"}, Token: "tok", APIPort: "1", Log: slog.New(slog.DiscardHandler)}
	port, closeProxy, err := StartScopedEgressProxyWithGrants(p, grants)
	if err != nil {
		t.Fatal(err)
	}
	defer closeProxy()
	if len(p.Allow) != 1 {
		t.Errorf("caller's proxy Allow was mutated: %v", p.Allow)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if got := connectStatus(t, addr, "granted.example.com:8443", "tok"); got != http.StatusForbidden {
		t.Errorf("CONNECT to granted host on an undeclared port = %d, want 403", got)
	}
	if got := connectStatus(t, addr, "other.example.com:443", "tok"); got != http.StatusForbidden {
		t.Errorf("CONNECT to an unlisted host = %d, want 403", got)
	}
}

func TestStartScopedEgressProxyWithGrants_refusesAPIHosts(t *testing.T) {
	for _, tc := range []struct {
		grant    string
		apiHosts []string
	}{
		{"*.internal:443", nil},
		{"gw.example.com:443", []string{"gw.example.com"}},
	} {
		grants, err := ParseEgressGrants([]string{tc.grant})
		if err != nil {
			t.Fatalf("%s: %v", tc.grant, err)
		}
		_, closeProxy, err := StartScopedEgressProxyWithGrants(&EgressProxy{Token: "tok", APIHosts: tc.apiHosts, Allow: []string{"x.test"}}, grants)
		if err == nil {
			closeProxy()
			t.Errorf("grant %s covering an API host was accepted", tc.grant)
		}
	}
	// The parser already refuses the literal alias.
	if _, err := ParseEgressGrants([]string{HostGatewayAlias + ":8080"}); err == nil {
		t.Error("parser accepted the host gateway alias")
	}
}

func TestGrantedProxy_noGrantsReturnsSameProxy(t *testing.T) {
	p := &EgressProxy{Allow: []string{"a.test"}, Token: "tok"}
	inner, err := grantedProxy(p, nil)
	if err != nil || inner != p {
		t.Errorf("grantedProxy with no grants = %p, %v, want the same proxy", inner, err)
	}
}

func policyTestRunner(hardened bool, policies map[string][]EgressGrant) ContainerRunner {
	return ContainerRunner{
		Hardened:       hardened,
		Runtime:        ContainerRuntime{Bin: "docker", Version: "24.0.7"},
		EgressPolicies: policies,
		ProviderProxy:  ScopedEgressProxyConfig{Allow: []string{"*.anthropic.com"}, APIPort: "8080", ContainerHost: "host.docker.internal"},
	}
}

func collectEvents() (func(Event), func() []Event) {
	var mu sync.Mutex
	var events []Event
	return func(e Event) { mu.Lock(); events = append(events, e); mu.Unlock() },
		func() []Event { mu.Lock(); defer mu.Unlock(); return slices.Clone(events) }
}

func TestApplyEgressPolicy_noPolicyIsUntouched(t *testing.T) {
	d := policyTestRunner(true, map[string][]EgressGrant{"other": {{Host: "a.example.com", Ports: []string{"443"}}}})
	d.ProxyURL = "http://x"
	emit, events := collectEvents()
	got, cleanup, err := d.applyEgressPolicy(SkillJob{Name: "plain"}, emit)
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if !reflect.DeepEqual(got, d) || len(events()) != 0 {
		t.Errorf("skill without a policy changed the runner or emitted events: %+v %v", got, events())
	}
}

func TestApplyEgressPolicy_refusesWithoutHardened(t *testing.T) {
	d := policyTestRunner(false, map[string][]EgressGrant{"meta": {{Host: "a.example.com", Ports: []string{"443"}}}})
	emit, _ := collectEvents()
	_, _, err := d.applyEgressPolicy(SkillJob{Name: "meta"}, emit)
	if err == nil || !strings.Contains(err.Error(), "requires --hardened") {
		t.Fatalf("err = %v, want a --hardened refusal", err)
	}
}

func TestApplyEgressPolicy_sidecarPath(t *testing.T) {
	grants := []EgressGrant{{Host: "a.example.com", Ports: []string{"443"}}}
	d := policyTestRunner(true, map[string][]EgressGrant{"meta": grants})
	d.Runtime = ContainerRuntime{Bin: "docker", DockerDesktop: true, Version: "24.0.7"}
	emit, events := collectEvents()
	got, cleanup, err := d.applyEgressPolicy(SkillJob{Name: "meta"}, emit)
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if !reflect.DeepEqual(got.Egress.Grants, grants) {
		t.Errorf("sidecar grants = %+v, want %+v", got.Egress.Grants, grants)
	}
	if len(d.Egress.Grants) != 0 {
		t.Error("shared runner config was mutated")
	}
	ev := events()
	if len(ev) != 1 || ev[0].Kind != KindEgress || ev[0].Text != "egress-policy: skill=meta grants=a.example.com:443" {
		t.Errorf("events = %+v", ev)
	}
}

func TestApplyEgressPolicy_hostProxyPath(t *testing.T) {
	grants, _ := ParseEgressGrants([]string{"a.example.com:443"})
	d := policyTestRunner(true, map[string][]EgressGrant{"meta": grants})
	d.ProxyURL = "http://stable"
	emit, events := collectEvents()
	got, cleanup, err := d.applyEgressPolicy(SkillJob{Name: "meta"}, emit)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProxyURL == "" || got.ProxyURL == d.ProxyURL || !strings.Contains(got.ProxyURL, "host.docker.internal:") {
		t.Fatalf("ProxyURL = %q, want a new scoped proxy URL", got.ProxyURL)
	}
	// Drive a denial through the scoped proxy so the cleanup has one to emit.
	userinfo, hostport, _ := strings.Cut(strings.TrimPrefix(got.ProxyURL, "http://"), "@")
	_, pw, _ := strings.Cut(userinfo, ":")
	_, port, _ := strings.Cut(hostport, ":")
	if code := connectStatus(t, "127.0.0.1:"+port, "a.example.com:22", pw); code != http.StatusForbidden {
		t.Fatalf("proxy answered %d, want 403", code)
	}
	cleanup()
	var denial bool
	for _, e := range events() {
		if e.Kind == KindEgress && strings.HasPrefix(e.Text, "egress-proxy: ") && strings.Contains(e.Text, "port not granted") {
			denial = true
		}
	}
	if !denial {
		t.Errorf("cleanup did not emit the recorded denial: %+v", events())
	}
}

func TestApplyEgressPolicy_hostProxyNeedsContainerHost(t *testing.T) {
	d := policyTestRunner(true, map[string][]EgressGrant{"meta": {{Host: "a.example.com", Ports: []string{"443"}}}})
	d.ProviderProxy.ContainerHost = ""
	emit, _ := collectEvents()
	if _, _, err := d.applyEgressPolicy(SkillJob{Name: "meta"}, emit); err == nil {
		t.Fatal("expected an error without a container host endpoint")
	}
}

func TestApplyEgressPolicy_concurrentSkillsStayIsolated(t *testing.T) {
	ga, _ := ParseEgressGrants([]string{"a.example.com:443"})
	gb, _ := ParseEgressGrants([]string{"b.example.com:8443"})
	d := policyTestRunner(true, map[string][]EgressGrant{"alpha": ga, "beta": gb})
	emit, _ := collectEvents()
	var wg sync.WaitGroup
	urls := make([]string, 2)
	for i, name := range []string{"alpha", "beta"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, cleanup, err := d.applyEgressPolicy(SkillJob{Name: name}, emit)
			if err != nil {
				t.Error(err)
				return
			}
			defer cleanup()
			urls[i] = got.ProxyURL
			time.Sleep(50 * time.Millisecond)
		}()
	}
	wg.Wait()
	if urls[0] == "" || urls[0] == urls[1] {
		t.Errorf("concurrent scans share a proxy: %v", urls)
	}
	if d.ProxyURL != "" {
		t.Error("shared runner ProxyURL was mutated")
	}
}
