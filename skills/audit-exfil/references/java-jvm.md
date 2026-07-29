# Java/JVM Exfiltration Review Notes

## SSRF

Search for java.net.URL/URI, HttpClient, URLConnection, OkHttp, Apache
HttpClient, RestTemplate, WebClient, Feign, webhook callbacks, URL previewers,
and importers. Safe code should resolve caller input through a fixed service
map or strict allowlist and handle redirects consistently. Check localhost
aliases, IPv6, numeric IP encodings, DNS rebinding, proxy settings, and cloud
metadata addresses.

## File Reads

Search for Files.read*, Path/Paths, FileInputStream, Resource loaders,
sendfile/resource controllers, ZipInputStream, TarArchiveInputStream, and
classpath or template lookup helpers. A safe path flow resolves against a
trusted root and checks canonical containment after normalization and symlink
resolution.

## XML And Document Parsing

Search for DocumentBuilderFactory, SAXParserFactory, XMLInputFactory,
TransformerFactory, SchemaFactory, JAXB, XPath, SVG, and office document
parsers. Confirm feature flags that disable DTDs, external general and
parameter entities, XInclude, and external schema/resource fetching.

## Response Leaks

Search for Spring error attributes, whitelabel error pages, stack traces,
debug actuator endpoints, exception mappers, and logs or upstream responses
returned to tenants or unauthenticated callers.
