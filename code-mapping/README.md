# Code Mapping — Library Manager for Venus 6

This directory contains structured code maps for every source file in the project.
These maps serve as a quick reference for understanding the codebase architecture,
function locations, cross-references, and audit findings.

## Files

| File | Description |
|------|-------------|
| `architecture-overview.md` | High-level architecture, dependency graph, data flow |
| `shared-js-map.md`         | `lib/shared.js` — all functions, constants, exports |
| `service-js-map.md`        | `lib/service.js` — service layer API |
| `cli-js-map.md`            | `cli.js` — CLI entry point |
| `rest-api-js-map.md`       | `rest-api.js` — REST API server |
| `main-js-map.md`           | `html/js/main.js` — GUI (NW.js) |
| `audit-findings.md`        | Security, dead code, logic issues found during audit |
| `update-code-map.js`       | Script to regenerate code maps without an AI agent |

## Regenerating

Run the update script from the project root:

```bash
node code-mapping/update-code-map.js
```

This will scan all source files and regenerate `generated-map.json` with
current function locations, exports, imports, constants, and line counts.
