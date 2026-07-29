# Go Exfiltration Review Notes

## SSRF

Search for http.Get, http.Client.Do, Request construction, reverse proxies,
webhook callbacks, importers, URL previewers, and custom transports. Safe code
should map user input to fixed destinations or enforce host/IP/scheme allowlists
before the request and after redirects. Inspect url.Parse behavior, proxy use,
DialContext hooks, DNS rebinding, localhost aliases, IPv6, and cloud metadata
addresses.

## File Reads

Search for os.Open, os.ReadFile, http.ServeFile, http.FileServer,
filepath.Join/Clean/Abs/EvalSymlinks, embed/static wrappers, archive/zip,
archive/tar, and object-store key construction. Require canonical containment
under a trusted root after normalization and symlink resolution.

## XML And Document Parsing

The standard encoding/xml package does not fetch external entities by itself,
but wrappers, custom Entity maps, template expansion, SVG/office parsers, or
cgo-backed XML libraries can. Report only when untrusted input can trigger a
file or network read or sensitive expansion.

## Response Leaks

Search for http.Error with raw internal errors, panic recovery that writes stack
traces, httputil.DumpRequest/Response, debug endpoints, pprof exposure, and log
or diagnostic APIs available to lower-privileged callers.
