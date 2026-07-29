# Ruby Exfiltration Review Notes

## SSRF

Search for Net::HTTP, OpenURI.open_uri, Faraday, HTTParty, RestClient, webhook
callbacks, importers, previewers, and integrations that accept URLs. Check
allowlists, scheme checks, redirect handling, proxy use, DNS rebinding,
IPv6/localhost aliases, and cloud metadata addresses. URI.parse alone is not a
security boundary.

## File Reads

Search for File.open/read/binread, IO.read, send_file, send_data, ActiveStorage
key selection, Pathname joins, archive extraction, and template/file lookup
helpers. Safe code should expand paths under a trusted root and enforce
containment after symlink resolution when user-controlled names are involved.

## XML And Document Parsing

Search for Nokogiri, REXML, Ox, XML schema validation, SVG processing, and
office document parsing. Report XXE only when untrusted XML can enable external
entities, DTD loading, XInclude, or external schema/resource fetching.

## Response Leaks

Search for Rails consider_all_requests_local, show_exceptions, exception
renderers, object inspection in JSON responses, debug endpoints, and logs or
diagnostics exposed to lower-privileged users.
