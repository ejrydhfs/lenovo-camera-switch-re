# Session archive

Generated 2026-10-06T06:26:39.986Z from session `01a10fbd-21ae-7707-a223-13fc02455f3b`.

## Layout

| Path | Contents |
| --- | --- |
| `manifest.json` | Index of everything below (counts, sizes, subagent list) |
| `session.jsonl` | The main session transcript, verbatim |
| `agents.json` | Live per-agent state captured while the session ran (model, system prompt, tools) |
| `jobs.json` | Background jobs: `completed` (recovered from transcripts) + `live` (running/recent at archive time) |
| `artifacts/` | Every file under the session artifact directory, verbatim |
| `viewer.html` | Standalone HTML viewer (all subagent sessions embedded) |

`artifacts/` is the important part: it holds each subagent's own
`<AgentId>.jsonl` transcript (recursively nested), the session's
`*.bash.log` / `*.eval.log` / `*.read.log` files with the **full, untruncated**
tool and background-job output, and `*.jsonl.tombstone` kill markers.

## Background jobs

17 completed jobs recovered from the transcripts (main + every subagent); full list in `jobs.json`. Per-job output lives in the owning transcript and in `artifacts/*.log`.

## Subagents (9)

- `AcpiEventChain` — 94 entries, 701542 bytes
- `BmofDecode` — 200 entries, 1180925 bytes
- `DotNetArch` — 107 entries, 564906 bytes
- `DotNetVerify` — 119 entries, 365140 bytes
- `GhidraFnHotkey` — 300 entries, 1305067 bytes
- `GhidraService` — 218 entries, 697997 bytes
- `KernelPoc` — 84 entries, 250086 bytes (killed)
- `LegionAndWeb` — 148 entries, 793434 bytes
- `LfcnMemory` — 56 entries, 278163 bytes

## Totals

50 files, 22147016 bytes.

Omitted:
- agents.json: the live per-agent registry (model / system prompt / tools) is host-only in-process state; the extension captures it while the session runs, it is not persisted for an external run
- jobs.json.live: the live background-job snapshot is host-only in-process state; jobs.json.completed is still recovered from every transcript
