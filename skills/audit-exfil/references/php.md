# PHP Exfiltration Review Notes

## SSRF

Search for curl_exec, file_get_contents on URLs, fopen wrappers, Guzzle,
Symfony HttpClient, webhook callbacks, importers, and previewers. Check
allow_url_fopen, redirect handling, proxy settings, scheme allowlists,
localhost aliases, IPv6/numeric IP forms, DNS rebinding, and cloud metadata
addresses.

## File Reads

Search for file_get_contents, readfile, fopen, include/require, SplFileObject,
Laravel/Symfony download helpers, storage path builders, zip/phar/tar handling,
and template or asset selection. Safe code should resolve under a trusted root
and enforce containment after normalization; basename or simple string replace
is usually not enough.

## XML And Document Parsing

Search for DOMDocument::loadXML, SimpleXML, XMLReader, libxml flags, SOAP, SVG,
and office document parsers. Report XXE only when untrusted XML can load
external entities, DTDs, XInclude, schemas, or file/network resources.

## Response Leaks

Search for display_errors, debug mode, Whoops, Laravel/Symfony exception pages,
var_dump/print_r in responses, exposed logs, and diagnostics that reveal
secrets, environment variables, headers, cookies, tokens, or internal service
responses.
