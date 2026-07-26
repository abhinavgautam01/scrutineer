# Audit Taxonomy

Use this reference while running `security-deep-dive`. It carries the detailed
methodology intentionally kept out of the always-loaded prompt.

## Trust Boundaries

Name the actors, what they control, whether they are trusted, and where that is
documented. For a small library this may be one or two rows; for a server,
package manager, build tool, plugin host, or framework it is a table.

Account for every public entry point in scope:

- Exported API, ABI, FFI, plugin loaders, callbacks, event buses, actor
  mailboxes, channels, and global hooks.
- HTTP, gRPC, Thrift, Cap'n Proto, JSON-RPC, XML-RPC, SOAP, REST, GraphQL,
  WebSockets, SSE, HTTP/2, QUIC streams, WebRTC data channels, raw TCP/UDP.
- Message-queue consumers: AMQP, Kafka, MQTT, NATS, ZeroMQ, cloud queues.
- CLI surfaces: argv, stdin, env, config, spool/drop directories, lock files,
  pid files, database-as-queue pollers, webhooks.
- File formats consumed and produced.
- IPC: anonymous pipes, Unix domain sockets, Windows named pipes, shared memory,
  D-Bus, Binder, XPC, COM.

Serialization formats such as Protobuf, Avro, MessagePack, CBOR, JSON, XML, and
ASN.1 are the wire format, not the channel. Note them with the boundary they
ride on.

The attacker is not automatically the developer calling the library. A value the
developer chooses, an operator-owned config, or a caller-owned local path is
trusted unless the project's documented threat model says otherwise. A file,
network message, deserialized object, environment value, or request field that
crosses a privilege boundary is attacker-controlled.

## Sink Classes

Before grepping, write down the project/language primitive names for each class
that applies. These are conceptual classes; languages name them differently.

- **Code execution**: string eval, dynamic method dispatch on computed names,
  reflection that resolves names to callables, code loaded from computed paths,
  regex engines with embedded-code constructs.
- **Command execution**: shell-outs or spawned processes where arguments are
  concatenated instead of passed as an array.
- **File operations**: open, read, write, delete, chmod, link, dynamic module or
  import paths.
- **Temporary files**: predictable names, creation in world-writable
  directories, missing `O_EXCL` or `O_NOFOLLOW`, cleanup and reuse across
  privilege boundaries.
- **Path handling**: join, normalize, canonicalize, or case-fold paths used for
  access decisions; traversal, symlink following, and case-insensitive
  filesystem confusion.
- **Archive extraction**: tar, zip, or similar unpacking where entry names
  become filesystem paths.
- **Deserialisation**: formats that instantiate types or call constructors
  during parse.
- **Parsing / format readers**: hand-rolled or specialized readers that turn
  external bytes/text into structure: config, manifest, wire protocol, file
  header, ad-hoc text format, or regex extractor.
- **Template or interpolation**: values reaching interpreted contexts without
  context-correct escaping: HTML, SQL, shell, regex, format strings, log lines.
- **Network**: clients following redirects, accepting input URLs, resolving
  input hostnames, using proxies, or changing TLS verification settings.
- **Validation**: public predicates or validator methods whose contract is "I
  tell you whether this input is safe."
- **Cryptography**: key derivation, IV handling, modes, padding, MAC
  verification, secret comparisons.
- **Memory safety**: raw pointers, unchecked indexing, manual allocation, FFI,
  type-punning casts, and for C/C++ the bounds/lifetime/integer arithmetic that
  feeds them.
- **Shared mutable state**: globals, prototype chains, module caches,
  environment variables, signal handlers, or any write read by another input
  path without coordination.
- **Concurrency**: check-then-act sequences where files, permissions, or shared
  state can change between check and act.
- **Resource consumption**: input-bounded allocation, recursion, iteration,
  caches, regex backtracking, decompression ratios.
- **Reflection or metaprogramming**: monkeypatches, prototype extensions, import
  hooks, global registrations, or anything changing caller behaviour outside the
  library namespace.
- **Round-trip integrity**: parse/serialize, encode/decode, marshal/unmarshal,
  escape/unescape pairs where values can change meaning across store and reload.
- **Authorization and access control**: authenticated users with distinct data,
  especially handlers loading records by request-supplied ID without checking
  ownership.
- **Field-level authorization for bulk-bound request bodies**: application or
  service code where externally supplied objects reach persistence,
  authorization, or privileged downstream calls. Focus on sensitive server-owned
  fields: owner/tenant IDs, roles, permissions, workflow status, security flags,
  prices, balances, and project-specific equivalents. Shape validation is not
  field-level authorization. Use `CWE-915` when it fits.
- **Agentic**: untrusted input reaching system prompts, tool definitions, tool
  arguments, model-readable tool output, agent loops, or paid model calls
  triggered by unauthenticated input.

## Inventory Completeness

Read the whole scoped source tree. Grep exhaustively, then confirm each hit is a
real sink and not a comment, test fixture, generated file, or unmodified
third-party code. Modified vendored code is first-party.

For C, C++, and other memory-unsafe code, make completeness auditable:

1. List project primitive names and wrappers first.
2. Run literal grep commands for memory primitives: at minimum `malloc`,
   `calloc`, `realloc`, `free`, `memcpy`, `memmove`, `strcpy`, `strncpy`,
   `sprintf`, `snprintf`, and any project-specific allocation/copy wrappers.
3. Record every command, its unique source-hit count, the inventory IDs produced
   from those hits, and every excluded hit with exact location and reason.
4. `hit_count` is the number of unique source locations returned by the command,
   not the number of inventory IDs. One source hit can produce multiple
   boundary-specific inventory entries.
5. Every unique source hit must be represented either by an inventory entry or
   an excluded hit. Do not silently skip uninteresting hits.

For other languages, apply the same discipline to that language's dangerous
primitives. If no memory-unsafe language is present, leave `grep_patterns` empty
for memory safety and explain why in `method.notes`.

## Six-Step Checklist

Work through inventory entries in order. Stop when a step rules the sink out and
record that step in `ruled_out`.

### Step 1: Trace the Input

Trace backwards from the sink to where the value originates. Name each hop:
variable, assignment, function return, argument, caller, boundary. Stop at the
library/application boundary. If the value is internal constant data and no
external input reaches it, rule it out.

For values like paths, identifiers, hosts, or format strings, also grep public
signatures and docs for other providers of the same value. A public API that
takes the sink input is a separate boundary.

### Step 2: Trust Boundary and Existing Controls

Name who controls the input and cite the boundary. When using a threat-model
report, cite the relevant `entry_points[i]` row:

- `attacker_controllable: "no"` rules the sink out as trusted input.
- `attacker_controllable: "conditional"` carries the row's condition as a
  precondition.

Before reporting, check whether the project already mitigates the danger:
centralized handler, framework default, sanitizer, escaping helper, type-system
rule, build flag, lint, or security header. Cite the control and rule it out
when it applies.

Also check for circular findings. If the precondition already grants the same
or stronger capability than the impact, write "precondition subsumes conclusion"
and rule it out.

For authentication, authorization, session validation, CSRF, rate-limit/lockout,
and credential-validation code, inspect absent, null, and empty-value branches
for every input that controls whether the security check runs. Report only if
omitting the input skips the security check while the protected operation
remains reachable without an equivalent guard. An explicit deny, error,
redirect-to-login, or equivalent rejection is fail-closed.

### Step 3: Validate

Write and run a reproduction. `validation` must include the script or shell
commands verbatim and the output. Output without the script is not actionable.

Before concluding a sink cannot reproduce, enumerate mechanisms that could
produce the value it consumes: argv, environment, glob expansion, archive
entries, dynamic definitions, deserialised keys, redirect targets, DNS, service
discovery, and equivalents. Try each relevant mechanism.

For published packages, validate against the latest shipped artefact from the
registry when package metadata is available. If the project is unpublished or
tool/service-shaped, the git checkout is the artefact.

For round-trip pairs, construct structural characters and test both
`decode(encode(x))` and `encode(decode(s))`. If meaning changes across a
store/reload cycle, trace what consumes the serialized form.

### Step 4: Prior Art

Check cached advisories first. Then search issues, PRs, and git history for the
function name, key strings, and prior fixes. Read maintainer comments. Check
whether a standard requires the behavior; standard-required behavior belongs in
`ruled_out` with a citation.

Record what you searched even when nothing was found. Set `discovered_via` to
the source that first identified the finding: `source`, `issue-tracker`,
`advisory`, or `documentation`.

### Step 5: Reach

For published libraries, start with Scrutineer's dependents cache and inspect
top dependents' published artefacts. Note exposed dependents and counterexamples
with line numbers. If the dependents cache is empty, direct packages.ecosyste.ms
queries are acceptable as a fallback.

For servers, build tools, package managers, CLIs, and other non-library targets,
trace input paths through the trust tiers from Phase 1.

Reach is data, not a final verdict. Use:

- `reachable` - shipped public entry point reaches the sink with
  attacker-controlled input.
- `harness_only` - only a test/fuzz/example/internal harness reaches it.
- `unclear` - neither could be established.

### Step 6: Rate

Rate severity from the validated path:

- Critical: fresh install, no preconditions.
- High: realistic preconditions normal deployments satisfy.
- Medium: significant attacker positioning, unusual configuration, or a chain
  of conditions.
- Low: unrealistic preconditions, narrow impact, or common deployment
  mitigation.

Rate confidence separately. Say what is certain and what depends on context.

Record `quality_tier` by sink class. For memory safety, heap overflow,
use-after-free, type confusion, and controllable write are high tier; stack
exhaustion, assertion failure, and fixed-offset null dereference are low tier.
For injection, shell/eval with attacker data is high tier; log injection is low
tier. A low-tier hit should make you keep tracing the same data path for a
higher-tier sink nearby before writing it up.
