package worker

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/alpha-omega-security/harness/egress"
)

const (
	minTCPPort        = 1
	maxTCPPort        = 65535
	grantPortSep      = "|"
	grantHostPortSep  = ":"
	grantEntrySep     = ","
	localhostSuffix   = ".localhost"
	localhostHostname = "localhost"
)

var grantHostPattern = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// EgressGrant is one operator-granted destination: a hostname (or *.domain)
// reachable only on Ports.
type EgressGrant struct {
	Host  string
	Ports []string
}

// ParseEgressGrants turns "host:port" entries into grants. Entries for the
// same host merge and the result is sorted and deduplicated so the formatted
// policy is stable. The rules mirror config.ValidateEgressPolicies, which the
// config package enforces first; they are repeated here because worker cannot
// be imported by config and the sidecar parses its own environment.
func ParseEgressGrants(entries []string) ([]EgressGrant, error) {
	byHost := map[string][]string{}
	for _, entry := range entries {
		host, port, err := parseEgressGrantEntry(entry)
		if err != nil {
			return nil, err
		}
		byHost[host] = append(byHost[host], port)
	}
	hosts := make([]string, 0, len(byHost))
	for host := range byHost {
		hosts = append(hosts, host)
	}
	slices.Sort(hosts)
	grants := make([]EgressGrant, 0, len(hosts))
	for _, host := range hosts {
		ports := byHost[host]
		slices.SortFunc(ports, func(a, b string) int {
			na, _ := strconv.Atoi(a)
			nb, _ := strconv.Atoi(b)
			return na - nb
		})
		grants = append(grants, EgressGrant{Host: host, Ports: slices.Compact(ports)})
	}
	return grants, nil
}

func parseEgressGrantEntry(entry string) (host, port string, err error) {
	if strings.TrimSpace(entry) != entry || entry == "" || strings.Contains(entry, "://") || strings.ContainsAny(entry, "/@ ") {
		return "", "", fmt.Errorf("egress grant %q must be host:port without a scheme, path or userinfo", entry)
	}
	host, port, ok := strings.Cut(entry, grantHostPortSep)
	if !ok || strings.Contains(port, grantHostPortSep) {
		return "", "", fmt.Errorf("egress grant %q must be a DNS hostname and a port (host:port)", entry)
	}
	n, convErr := strconv.Atoi(port)
	if convErr != nil || n < minTCPPort || n > maxTCPPort || strconv.Itoa(n) != port {
		return "", "", fmt.Errorf("egress grant %q has an invalid port (want %d to %d)", entry, minTCPPort, maxTCPPort)
	}
	host = strings.ToLower(host)
	if !grantHostPattern.MatchString(host) || net.ParseIP(host) != nil || strings.Trim(host, "0123456789.") == "" {
		return "", "", fmt.Errorf("egress grant %q must name a DNS hostname or *.domain, not an IP address", entry)
	}
	if host == localhostHostname || strings.HasSuffix(host, localhostSuffix) || host == HostGatewayAlias {
		return "", "", fmt.Errorf("egress grant %q names a local or host address, which grants cannot cover", entry)
	}
	return host, port, nil
}

// FormatEgressGrants renders grants as "host:p1|p2,host2:p" for the sidecar
// environment and the scan record. The output is deterministic for a given
// set of grants as ParseEgressGrants sorts them.
func FormatEgressGrants(g []EgressGrant) string {
	parts := make([]string, 0, len(g))
	for _, grant := range g {
		parts = append(parts, grant.Host+grantHostPortSep+strings.Join(grant.Ports, grantPortSep))
	}
	return strings.Join(parts, grantEntrySep)
}

// ParseEgressGrantsEnv is the inverse of FormatEgressGrants. An empty string
// means no grants.
func ParseEgressGrantsEnv(s string) ([]EgressGrant, error) {
	var entries []string
	for item := range strings.SplitSeq(s, grantEntrySep) {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		host, ports, ok := strings.Cut(item, grantHostPortSep)
		if !ok {
			return nil, fmt.Errorf("egress grant %q must be host:port", item)
		}
		for port := range strings.SplitSeq(ports, grantPortSep) {
			entries = append(entries, host+grantHostPortSep+port)
		}
	}
	if len(entries) == 0 {
		return nil, nil
	}
	return ParseEgressGrants(entries)
}

func grantHosts(g []EgressGrant) []string {
	hosts := make([]string, 0, len(g))
	for _, grant := range g {
		hosts = append(hosts, grant.Host)
	}
	return hosts
}

// grantedProxy returns the proxy that should serve p with grants applied: a
// fresh Proxy whose allowlist is p.Allow plus the granted hosts. p itself is
// never mutated. With no grants it returns p. A grant naming an API host is
// refused so a policy can never reach host services.
func grantedProxy(p *EgressProxy, grants []EgressGrant) (*EgressProxy, error) {
	if len(grants) == 0 {
		return p, nil
	}
	for _, g := range grants {
		if err := checkGrantNotAPIHost(p, g); err != nil {
			return nil, err
		}
	}
	return &EgressProxy{
		Allow:           append(slices.Clone(p.Allow), grantHosts(grants)...),
		Token:           p.Token,
		APIPort:         p.APIPort,
		APIHosts:        p.APIHosts,
		HostPorts:       p.HostPorts,
		Log:             p.Log,
		GatewayDialHost: p.GatewayDialHost,
	}, nil
}

func checkGrantNotAPIHost(p *EgressProxy, g EgressGrant) error {
	apiHosts := append([]string{HostGatewayAlias}, p.APIHosts...)
	for _, h := range apiHosts {
		if egress.HostAllowed([]string{g.Host}, h) {
			return fmt.Errorf("egress grant for %q covers host service %q, which policies cannot reach", g.Host, h)
		}
	}
	return nil
}

// egressPortGuard enforces declared ports for hosts that only an EgressGrant
// allows. Hosts on base keep their any-port behaviour and hosts that match no
// grant fall through so the inner proxy applies its own allowlist.
func egressPortGuard(token string, base []string, grants []EgressGrant, log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, port, ok := proxyRequestTarget(r)
		if !ok || egress.HostAllowed(base, host) {
			next.ServeHTTP(w, r)
			return
		}
		matched := false
		for _, g := range grants {
			if !egress.HostAllowed([]string{g.Host}, host) {
				continue
			}
			matched = true
			if slices.Contains(g.Ports, port) {
				next.ServeHTTP(w, r)
				return
			}
		}
		if !matched {
			next.ServeHTTP(w, r)
			return
		}
		denyUngrantedPort(w, r, token, log, host, port)
	})
}

func denyUngrantedPort(w http.ResponseWriter, r *http.Request, token string, log *slog.Logger, host, port string) {
	if !validProxyAuthorization(token, r.Header.Get("Proxy-Authorization")) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="harness"`)
		http.Error(w, "proxy authorization required", http.StatusProxyAuthRequired)
		return
	}
	if log != nil {
		log.Warn("egress denied", "method", r.Method, "host", host, "port", port,
			"reason", "port not granted by egress policy")
	}
	http.Error(w, "egress to "+host+" port "+port+" is not granted", http.StatusForbidden)
}

// proxyRequestTarget extracts the destination host and port of a proxy request
// exactly as the inner proxy will dial it. A target without an explicit port is
// dialed on 443 for both CONNECT and forward requests (see splitProxyTarget),
// so the gate checks that port rather than a scheme default the proxy would
// not use. Relative forward requests report ok=false so the inner proxy
// rejects them.
func proxyRequestTarget(r *http.Request) (host, port string, ok bool) {
	if r.Method == http.MethodConnect {
		host, port = splitProxyTarget(r.Host)
		return host, port, true
	}
	if r.URL == nil || !r.URL.IsAbs() {
		return "", "", false
	}
	host, port = splitProxyTarget(r.URL.Host)
	return host, port, true
}
