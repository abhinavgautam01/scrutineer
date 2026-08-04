ARG POUTINE_AMD64_LOCK=v1.1.6@sha256:abde716599a65608b023a69ed9316e5f083a7bca48612151c2720835883757ea
ARG POUTINE_ARM64_LOCK=v1.1.6@sha256:460c90300c6329106b551c150682d12e457365f6436a6cbbd08fe79eb9a98131

FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# COMMIT is the git SHA being built. .git is excluded from the build context
# (.dockerignore), so the Go VCS stamp is unavailable here; pass it explicitly
# with `docker build --build-arg COMMIT=$(git rev-parse HEAD)` to surface it on
# the settings page. Empty when not supplied.
ARG COMMIT=""
RUN CGO_ENABLED=0 go build -ldflags "-X main.commit=${COMMIT}" -o /scrutineer ./cmd/scrutineer

FROM node:26-alpine@sha256:e88a35be04478413b7c71c455cd9865de9b9360e1f43456be5951032d7ac1a66 AS claude
RUN npm install -g @anthropic-ai/claude-code@2.1.220

FROM python:3.15.0b4-alpine@sha256:c40ec5a55436b283c1570e649ff40a8188e7e0221d7f285e624b20167c712ead AS python-tools
RUN pip install --no-cache-dir semgrep==1.167.0 "setuptools<81"

FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS go-tools
ARG POUTINE_AMD64_LOCK
ARG POUTINE_ARM64_LOCK
ARG TARGETARCH
RUN apk add --no-cache curl git
RUN GOBIN=/out go install github.com/git-pkgs/git-pkgs@v0.15.3 && \
    GOBIN=/out go install github.com/git-pkgs/brief/cmd/brief@v0.9.3
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) arch=x86_64; lock="${POUTINE_AMD64_LOCK}" ;; \
      arm64) arch=arm64;  lock="${POUTINE_ARM64_LOCK}" ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    tag="${lock%@*}"; \
    sha="${lock#*@sha256:}"; \
    curl -fsSL -o /tmp/poutine.tgz \
      "https://github.com/boostsecurityio/poutine/releases/download/${tag}/poutine_Linux_${arch}.tar.gz"; \
    echo "${sha}  /tmp/poutine.tgz" | sha256sum -c -; \
    tar -xzf /tmp/poutine.tgz -C /out poutine; \
    chmod 0755 /out/poutine; \
    rm /tmp/poutine.tgz; \
    /out/poutine version

# vid links tree-sitter grammars (C), so unlike the main binary it needs
# cgo; build-base provides gcc and musl headers, matching the musl-based
# final image.
FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS vid-build
RUN apk add --no-cache build-base git
RUN GOBIN=/out CGO_ENABLED=1 go install github.com/andrew/VID/cmd/vid@v0.1.0

FROM rust:1.97-alpine@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900 AS zizmor-build
RUN apk add --no-cache build-base linux-headers
RUN cargo install --locked --root /out zizmor@1.28.0

FROM python:3.15.0b4-alpine@sha256:c40ec5a55436b283c1570e649ff40a8188e7e0221d7f285e624b20167c712ead
RUN apk add --no-cache git ca-certificates bash nodejs coreutils && \
    rm -f /usr/local/bin/pip* /usr/local/bin/idle* /usr/local/bin/pydoc*

# scrutineer binary
COPY --from=build /scrutineer /usr/local/bin/scrutineer

# claude cli
COPY --from=claude /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=claude /usr/local/bin/claude /usr/local/bin/claude

# semgrep
COPY --from=python-tools /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages
COPY --from=python-tools /usr/local/bin/semgrep* /usr/local/bin/
COPY --from=python-tools /usr/local/bin/pysemgrep /usr/local/bin/

# go tools
COPY --from=go-tools /out/* /usr/local/bin/

# zizmor
COPY --from=zizmor-build /out/bin/zizmor /usr/local/bin/zizmor

# vid
COPY --from=vid-build /out/vid /usr/local/bin/vid

# Non-root user (T1/T11: reduce blast radius)
RUN adduser -D -h /home/scrutineer scrutineer && \
    mkdir -p /data && chown scrutineer:scrutineer /data
USER scrutineer

EXPOSE 8080
ENTRYPOINT ["scrutineer"]
CMD ["-addr", "0.0.0.0:8080", "-data", "/data"]
