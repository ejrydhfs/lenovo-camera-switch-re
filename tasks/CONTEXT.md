# Shared context for all subagents (read STATE.md too)
$W = /home/user/Downloads/lenovo-camera-switch-re
Read $W/STATE.md first: verified ground truth (machine, ACPI, WMI GUID->driver table, Windows payload, tooling). Do not re-derive.
Binaries: $W/10-extracted/code$getextractpath$/source/ (literal `$` in path; quote it).
Existing string dumps: $W/70-evidence/strings-<name>.txt, strings16-<name>.txt
ACPI: raw $W/20-acpi/aml/*.aml, disassembly $W/20-acpi/dsl/*.dsl
Upstream kernel sources fetched: $W/40-kernel-src/*.c
Root ops: docker run --rm --privileged -v <dir>:/work debian:stable-slim <cmd>   (no sudo password; docker works)
Workspace files are owned by uid 1000; root-created files need: docker ... chown -R 1000:1001 /work
Write ONLY the files named in your brief. Tag inferences [INFERENCE]. Cite file:line.
