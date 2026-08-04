---
name: poutine
description: Audit CI and build pipelines with Poutine and map native findings into Scrutineer's findings shape.
license: MIT
compatibility: Requires `poutine` (https://github.com/boostsecurityio/poutine) and `python3` on PATH.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: findings
  scrutineer.model: mid
---

# poutine

Run Poutine against the local repository and map its build-pipeline findings into Scrutineer's findings shape. This skill is tool-driven and does not need model analysis.

## Workspace

- `./src` - the cloned repository
- `./scripts/scan.py` - the Poutine wrapper and native-output mapper
- `./report.json` - write the findings report here
- `./schema.json` - output shape

## What to do

```bash
python3 scripts/scan.py > ./report.json
```

The wrapper runs `poutine analyze_local` across the repository, honors repository-local Poutine configuration, disables Poutine's version-check request, and converts rules and findings deterministically. It handles a missing binary, command failure, and malformed output itself; do not add model-generated findings or retry logic.
