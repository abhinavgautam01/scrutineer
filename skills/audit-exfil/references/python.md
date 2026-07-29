# Python Exfiltration Review Notes

## SSRF

Search for requests, httpx, aiohttp, urllib, boto client endpoints, webhook
callbacks, importers, previewers, and URL validators. Treat a path as safe only
when the code maps user input to an allowlisted host or service before the
request and enforces the same decision after redirects. Check scheme allowlists,
credentials in URLs, proxy settings, redirects, IPv6 literals, decimal or octal
IPv4 forms, DNS rebinding, and access to cloud metadata addresses.

## File Reads

Search for open, pathlib.Path.open/read_text/read_bytes, os.path joins,
send_file, FileResponse, static file helpers, zipfile, tarfile, shutil
extraction, and object-storage key construction. A lexical clean is not enough:
the code must join against a trusted root and enforce containment after
normalization and symlink resolution. Watch for double decoding and mixed path
separators.

## XML And Document Parsing

Search for lxml, ElementTree, minidom, SAX, defusedxml bypasses, YAML/XML
document imports, SVG parsing, DOCX/XLSX metadata reads, and schema validation.
Report XXE only when untrusted XML reaches a parser with DTD, entity, XInclude,
or external resource loading enabled.

## Response Leaks

Search for DEBUG=True, traceback responses, exception formatters, repr(object)
in HTTP responses, headers/cookies reflected into errors, and logs returned
through user-accessible APIs. Operator-only logs are not a finding unless a
less-privileged caller can retrieve them.
