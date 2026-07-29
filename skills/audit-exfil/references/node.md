# Node Exfiltration Review Notes

## SSRF

Search for fetch, axios, got, request, undici, node:http, proxy agents, webhook
callbacks, URL previewers, importers, and integrations that accept
caller-provided endpoints. Safe code should use a fixed service map or strict
host allowlist and re-check redirects. Inspect URL parsing differences, encoded
hosts, username/password fields, IPv6, localhost aliases, cloud metadata
addresses, and DNS rebinding windows.

## File Reads

Search for fs.readFile, createReadStream, sendFile, res.download, serve-static
wrappers, path.join/resolve, multer uploads, archive extraction, and template or
asset lookup helpers. Report traversal only when an untrusted path can escape
the intended root or select a sensitive object. Require evidence about
normalization, absolute paths, symlinks, percent decoding, and platform path
separators.

## XML And Document Parsing

Search for libxmljs, xml2js, fast-xml-parser, sax, xmldom, SVG processors, and
office document parsers. Confirm whether DTDs, external entities, XInclude,
schema fetching, or network/file loaders are enabled for untrusted input before
reporting.

## Response Leaks

Search for Express/Fastify/Next error handlers, development mode, stack traces,
JSON.stringify of internal errors, logging endpoints, and response bodies that
include secrets, headers, tokens, environment variables, or upstream internal
responses.
