# 02 — LFCN SystemMemory region layout & CAMS byte

> Intended path: `$W/20-acpi/analysis/02-lfcn-layout.md` (this agent is read-only; document returned as data).

## 0. Source

- DSDT.dsl:13785 — `OperationRegion (LFCN, SystemMemory, 0xCCF7D198, 0x01FE)`, inside `Scope (\)`.
- DSDT.dsl:13786–13849 — `Field (LFCN, AnyAcc, Lock, Preserve) { ... }`.
- Region covers physical `[0xCCF7D198, 0xCCF7D396)` — 0x01FE = 510 bytes.

## 1. Byte offset of every field (from region base)

Bit fields are byte-aligned unless noted; `Offset(0x94)` is honored.

| # | Name | Byte offset | Size | Notes |
|---|------|-------------|------|-------|
| 1 | `PS2V` | 0x000 | 1 B | |
| 2 | `KBID` | 0x001 | 1 B | |
| 3 | `MCSZ` | 0x002 | 1 B | |
| 4 | `OKRB` | 0x003 | 1 B | |
| 5 | `EDID` | 0x004 | 128 B (1024 bits) | |
| 6 | `TPTY` | 0x084 | 1 B | |
| 7 | `TPTP` | 0x085 | 2 B (16 bits) | |
| 8 | `TPNY` | 0x087 | 1 B | |
| 9 | `TPNP` | 0x088 | 2 B (16 bits) | |
| 10 | `UMAB` | 0x08A | 1 B | |
| 11 | `ENQT` | 0x08B | 1 B | |
| 12 | `DYTP` | 0x08C | 4 B (32 bits) | |
| 13 | `FCAP` | 0x090 | 2 B (16 bits) | |
| 14 | `VSTD` | 0x092 bit0 | 1 bit | |
| — | *(reserved)* | 0x092 bit1 | 1 bit | pad |
| 15 | `VFBC` | 0x092 bit2 | 1 bit | |
| 16 | `VMYH` | 0x092 bit3 | 1 bit | |
| 17 | `VSTP` | 0x092 bit4 | 1 bit | |
| 18 | `VAPM` | 0x092 bit5 | 1 bit | |
| 19 | `VAQM` | 0x092 bit6 | 1 bit | |
| 20 | `VIEP` | 0x092 bit7 | 1 bit | |
| 21 | `VIBS` | 0x093 bit0 | 1 bit | |
| 22 | `VCQL` | 0x093 bit1 | 1 bit | |
| 23 | `VAAA` | 0x093 bit2 | 1 bit | |
| 24 | `VMMC` | 0x093 bit3 | 1 bit | |
| — | *(reserved)* | 0x093 bit4 | 1 bit | pad |
| — | *(reserved)* | 0x093 bit5 | 1 bit | pad |
| — | **`Offset (0x94)`** | — | — | forces next field to byte 0x094; remaining 2 bits of 0x093 discarded |
| 25 | `MYHC` | 0x094 | 1 B | |
| 26 | `MMCC` | 0x095 | 1 B | |
| 27 | `SMYH` | 0x096 | 1 B | |
| 28 | `SMMC` | 0x097 | 1 B | |
| 29 | `CICF` | 0x098 bits0–3 | 4 bits | nibble |
| 30 | `CICM` | 0x098 bits4–7 | 4 bits | nibble |
| 31 | `BDDN` | 0x099 | 256 B (2048 bits) | |
| 32 | `NVHC` | 0x199 | 1 B | |
| 33 | `PBID` | 0x19A | 1 B | |
| **34** | **`CAMS`** | **0x19B** | **1 B** | **camera-privacy gate bit (see §4)** |
| 35 | `PANT` | 0x19C | 1 B | |
| 36 | `DSMF` | 0x19D | 1 B | |
| 37 | `RDOC` | 0x19E | 1 B | |
| 38 | `TRLV` | 0x19F | 1 B | |
| 39 | `GTYP` | 0x1A0 | 1 B | |
| 40 | `RGBD` | 0x1A1 | 1 B | |
| 41 | `MCSK` | 0x1A2 | 1 B | |
| 42 | `OCCS` | 0x1A3 | 1 B | |
| 43 | `COCC` | 0x1A4 | 1 B | |
| 44 | `GOCC` | 0x1A5 | 1 B | |
| 45 | `GCCO` | 0x1A6 | 2 B (16 bits) | |
| 46 | `GCOP` | 0x1A8 | 1 B | |
| 47 | `GVCO` | 0x1A9 | 2 B (16 bits) | |
| 48 | `GVOP` | 0x1AB | 1 B | |
| 49 | `GSYN` | 0x1AC | 1 B | |
| 50 | `CMSP` | 0x1AD | 2 B (16 bits) | |
| 51 | `PVSD` | 0x1AF | 1 B | |
| 52 | `PMID` | 0x1B0 | 2 B (16 bits) | |
| 53 | `PPID` | 0x1B2 | 2 B (16 bits) | |
| 54 | `GSNM` | 0x1B4 | 1 B | |
| 55 | `CNFG` | 0x1B5 | 1 B | |
| 56 | `RSVD` | 0x1B6 | 72 B (576 bits) | |
| — | *end* | 0x1FE | — | exactly the declared region length |

**Reconciliation:** last field ends at `0x1B6 + 0x48 = 0x1FE`, matching the region length `0x01FE`. Offset math is self-consistent.

### CAMS final offset / physical address

- `CAMS` byte offset within LFCN = **0x19B**.
- Physical address = `0xCCF7D198 + 0x19B` = **0xCCF7D333**.
- Cross-check: `tasks/07-kernel-poc.md` in the repo independently states the same (`offset 0x19B -> 0xCCF7D333`). ✅

### 0x20-byte dump window intended around `CAMS`

CAMS = LFCN+0x19B, so the requested 0x20 bytes are physical **0xCCF7D333 .. 0xCCF7D352** (covers `CAMS, PANT, DSMF, RDOC, TRLV, GTYP, RGBD, MCSK, OCCS, COCC, GOCC, GCOP, GVCO[0]`).
*(Bytes not obtained — see §4.)*

## 2. Name collisions / aliasing check (`grep` over all 18 .dsl files)

Pattern `LFCN|CAMS|\bCNFG\b|\bVSTD\b|\bMYHC\b` and `Name \((CAMS|VSTD|MYHC|CNFG|LFCN)`:

| Symbol | Definitions | References | Verdict |
|--------|-------------|------------|---------|
| `LFCN` | 1 — OperationRegion DSDT:13785 only | 0 elsewhere | no second `Field(LFCN)`; no aliasing |
| `CAMS` | 1 — field unit DSDT:13826 | DSDT:6744 (`HSP3._UPC`), DSDT:6830 (`CAMA._STA`) | single definition, no `Name()` shadow |
| `CNFG` | 1 — field unit DSDT:13847 | DSDT:24743, 24847, 24858 (`WMIU` device-id queries, `CNFG == One`) | single definition |
| `VSTD` | 1 — field unit DSDT:13801 | none | defined but unread by AML [INFERENCE: consumed by firmware only] |
| `MYHC` | 1 — field unit DSDT:13817 | none | defined but unread by AML [INFERENCE] |

**No** `Name (CAMS|VSTD|MYHC|CNFG|LFCN)` object exists anywhere; all five are solely LFCN field units in scope `\`. No shadowing, no duplicate region, no aliasing.

### Overlapping OperationRegions (address-interval check, all tables)

Every `SystemMemory` region was enumerated. The only region in the same reserved block as LFCN is:

- SSDT6.dsl:118 `OperationRegion (HGOP, SystemMemory, 0xCCF7DF18, 0x11)`.

LFCN ends at `0xCCF7D396`; HGOP starts at `0xCCF7DF18` → **gap of 0xB82 bytes, no overlap.** All other SystemMemory regions are in ACPI NVS/tables or high MMIO (`0xCDFxxxxx`, `0xFE00D4xx`, `0xFED8xxxx`, `0xFF00D5xx`), far from `0xCCF7D198`. **No collisions.**

[INFERENCE] HGOP (dGPU/NVIDIA mailbox) and LFCN sharing one reserved block suggests this block is a general firmware-mailbox window, which strengthens the plausibility of LFCN being real (see §3).

## 3. Is base `0xCCF7D198` plausible / valid on this machine? — **YES**

### Method & raw evidence

`/proc/iomem` under this (non-root) user is **address-suppressed** — the kernel blanks the ranges unless the reader has `CAP_SYS_ADMIN` (Linux ≥5.8 behaviour). Observed verbatim snippet:

```
$ cat /proc/iomem
00000000-00000000 : Reserved
00000000-00000000 : System RAM
...
00000000-00000000 : ACPI Tables
00000000-00000000 : System RAM
```

(All 16-digit ranges are `00000000-00000000`; names are real, addresses redacted. This is why the docker root recipe in the task exists.)

Authoritative, world-readable e820 view via `/sys/firmware/memmap/*/{start,end,type}` (real addresses):

```
# idx  start        end          type
06    0x09f0f000   0x0bab68fff  System RAM
07    0x0bab69000  0x0bbd68fff  Reserved
08    0x0bbd69000  0x0c9f7efff  System RAM
09    0x0c9f7f000  0x0ccf7efff  Reserved          <-- LFCN lives here
10    0x0ccf7f000  0x0cdf7efff  ACPI Non-volatile Storage
11    0x0cdf7f000  0x0cdffefff  ACPI Tables
12    0x0cdfff000  0x0cdffffff  System RAM
13    0x0ce000000  0x0cfffffff  Reserved
```

### Verdict

- `LFCN` `[0xCCF7D198, 0xCCF7D396)` falls **entirely inside memmap entry #9: `Reserved`, `0xC9F7F000–0xCCF7EFFF`** (48 MiB).
- Base is `0xC9F7F000 + 0x2FFE198` (0x1E68 below the reserved-block top); the block top `0xCCF7F000` is exactly where the 16 MiB **ACPI Non-volatile Storage** block (#10) begins.
- Not System RAM, not ACPI Tables/NVS — a dedicated e820 **Reserved** window, immediately below ACPI NVS, is the classic place for BIOS/firmware mailboxes.
- Corroborating: HGOP (SSDT6, dGPU mailbox) at `0xCCF7DF18` sits in the same reserved block, and all Lenovo runtime structures (`GNVS`/`MDBG`/`USBC` at `0xCDFxxxxx`) sit in the adjacent ACPI NVS block.
- The value is **not a sentinel/magic** (`0xDEADBEEF`, `0xFFFFFFFF`, etc.). It is a coherent runtime-programmed address in the same 4 KiB sub-range as HGOP. [INFERENCE] Round-off patterns ending `…D198`/`…DF18` under `0xCCF7F000` imply BIOS-computed mailbox offsets, not a hard-coded bogus constant.

**Conclusion:** `address_valid = true`. The region is a genuine, OS-mappable firmware mailbox area (e820 Reserved). ACPI `SystemMemory` OperationRegions over Reserved (non-RAM) ranges are mapped by the kernel via `acpi_os_map_memory`/`ioremap` without the “ioremap on RAM” hazard.

## 4. Runtime byte read at `0xCCF7D333` — could not be executed by this agent

**Blocker:** this subagent has only `read`/`grep`/`glob`/`web_search` (read-only, **no shell/exec tool**). The task’s docker path (`docker run --privileged … busybox devmem` / `/dev/mem` via gcc) therefore could not be run here. **No bytes were observed; `raw_bytes` is reported as `null` rather than fabricated.**

Exact **read-only** recipe for the main agent / a shell-capable worker (from STATE.md — docker works, no sudo):

```bash
# 1. Confirm the range classification (root sees real addresses):
docker run --rm --privileged -v /proc:/host/proc debian:stable-slim cat /host/proc/iomem | grep -i -A2 -B2 ccf7d

# 2. Read CAMS and following bytes (busybox devmem, byte-wide READ, no writes):
for off in $(seq 0 31); do
  addr=$((0xCCF7D333 + off))
  printf '%08x: ' "$addr"
  docker run --rm --privileged debian:stable-slim busybox devmem $(printf '0x%X' "$addr") 8
done

# 3. Fallback if devmem absent — READ-ONLY C program:
#    open("/dev/mem", O_RDONLY|O_SYNC); mmap(page-aligned 0xCCF7D000, 0x1000, PROT_READ, MAP_SHARED, fd, 0);
#    print 32 bytes at +0x333. No write()/ioctl on /dev/mem, no munmap-then-write.
```

Caveats to expect (report honestly):
- `CONFIG_STRICT_DEVMEM` blocks `/dev/mem` access to System RAM but generally **permits** e820-Reserved ranges; if it still returns `EPERM`, note it — that is a config limitation, not evidence the mailbox is fake.
- Reading `0xCCF7D333` while the firmware owns it is a single byte/word **read**; it cannot alter the machine (unlike writes).

[INFERENCE] Because `CAMS` gates `HSP3._UPC` and `CAMA._STA` and is only *evaluated* by AML at boot/hotplug, a read of the live byte should show either `0x00` or `0x01` (or another non-zero enable value); a stuck `0xFF` would point to unmapped/firmware-undefined memory.

## 5. Summary deliverables

- **CAMS offset:** `0x19B` from LFCN base; **physical `0xCCF7D333`**.
- **Aliasing:** none — every symbol uniquely defined in the single LFCN region.
- **Address validity:** **valid** — inside e820 Reserved `0xC9F7F000–0xCCF7EFFF`, adjacent to ACPI NVS, co-located with another firmware mailbox (HGOP).
- **Raw bytes:** not obtained (no exec tool); read-only recipe supplied.

## 6. Hardware-write safety constraint (user directive) — compliance

All work in this document and every command proposed is **read-only**. Per the standing directive:

- **No** EC writes, **no** ACPI methods that change state (only static DSDT/SSDT decompilation was used), **no** VPC commands, **no** `/dev/mem` writes, **no** sysfs stores, **no** `camera_power` writes.
- The §4 recipe uses only reads: `cat /proc/iomem`, `busybox devmem <addr> 8` (read form), and an `O_RDONLY|O_SYNC` + `PROT_READ` `mmap` of `/dev/mem`. **Nothing** writes hardware.
- No driver unbind/rebind of `ideapad_wmi` or any other module was performed or proposed. Loading a read-only kernel module remains permitted and is not required by this task.
- No step of this task required a hardware write, so **no step had to be stopped**; the only non-executable step (raw byte read) was blocked by absence of a shell tool, and was reported rather than worked around with a write.