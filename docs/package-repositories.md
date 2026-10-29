# Package repositories

`package_repositories` points the package managers inside scan containers at an
existing package repository or caching proxy (Artifactory, Nexus or
[git-pkgs/proxy](https://github.com/git-pkgs/proxy)). Scrutineer sets each
package manager's native environment variables, so no files are written into
the scanned workspace.

```yaml
package_repositories:
  git_pkgs_proxy: https://pkgs.example.com
  # Optional per-ecosystem override.
  npm: https://artifactory.example.com/api/npm/npm/
```

## Environment set per ecosystem

| Key | Environment variables | git-pkgs/proxy path |
| --- | --- | --- |
| `npm` | `npm_config_registry`, `YARN_NPM_REGISTRY_SERVER`, `BUN_CONFIG_REGISTRY` | `/npm/` |
| `pypi` | `PIP_INDEX_URL`, `UV_DEFAULT_INDEX` | `/pypi/simple/` |
| `go` | `GOPROXY` | `/go` |
| `pub` | `PUB_HOSTED_URL` | `/pub` |
| `hex` | `HEX_MIRROR` | `/hex` |

An explicit per-ecosystem key always beats the `git_pkgs_proxy` preset. A
trailing slash on the proxy base URL is ignored.

Go gets the bare URL as `GOPROXY`, with no `,direct` suffix, so a miss never
silently falls back to the public upstream. Checksum verification through
`GOSUMDB` is unchanged.

## Egress

Without `--hardened` the repository hosts are added to the egress allowlist
automatically. Under `--hardened` they are not. Grant `host:443` with
`egress_policies` or `scan_egress_policies` instead (see
[egress-policies.md](egress-policies.md)).

## Validation

Scrutineer rejects the config at startup when a URL:

- is not an absolute `https` URL
- contains credentials, a query string or a fragment
- contains `,` or `|`, which `GOPROXY` reads as list separators
- uses `localhost`, a `.localhost` name or the container host gateway
- is an IP literal that is loopback, private, link-local or unspecified

The scan egress proxy blocks private and loopback addresses, so those
repositories could never be reached. Credentials must stay out of config URLs.

## Not yet supported

- Credentials
- Custom CA certificates
- Explicit upstream fallback
- Cargo, Bundler/RubyGems, Maven/Gradle, NuGet and Composer
- Internally hosted repositories on private addresses
- The `--no-container` runner (a warning is logged)
