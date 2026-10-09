# Reverse engineering: Lenovo camera toggle switch driver (82JU) - MASTER REPORT

Target: `/home/user/Downloads/01lf0aafar2w6jb0.exe`
sha256 `3e30c034e8a4cf310547d44fc663857607f7f365d1d5d8b80954b57c5bcf7b6d`
Machine: Lenovo Legion 5 15ACH6H (`82JU`), BIOS `GKCN65WW`, kernel `7.2.7-arch1-1`.

**No hardware write was performed at any point** (see `70-evidence/03-hardware-integrity-audit.md`, including the
one precise disclosure about the `camera_power` read path).

A corrected `ideapad-laptop` was implemented, built and verified on this machine to test the gap (`60-driver/`).
Physically toggling the switch settled it - the WMI events and the camera's USB presence already carry the state,
so **no new Linux driver is needed** (§7).

Several artifacts cited below (the original installer, the unpacked Lenovo payloads, and the full Ghidra
decompilation dumps) are **not redistributed in this repository** - see §6. Line references to
`decompile.txt` still point at that dump; `50-ghidra/scripts/*.java` regenerates it from the installer.

---

## 1. TL;DR - the answer

The camera toggle switch is **not** reported by the driver package itself. The package is a user-mode
"Fn and function keys" service bundle; the switch state is produced by **firmware** and reaches the OS through
**two independent channels**, both now identified:

| Channel | Producer | Transport | Camera ON | Camera OFF |
|---|---|---|---|---|
| **Transition event** (live, measured) | EC -> `_QDF` -> `Notify(WMIU,0xD0)` -> `_WED` | ACPI-WMI GUID `8FC0DE0C-B4E4-43FD-B0F3-8871711C1294`, notify `0xD0`, class `LENOVO_UTILITY_EVENT` (ROOT\WMI) | event id `0x0C` | event id `0x0D` |
| **Camera USB presence** (live, measured) | EC cuts the camera's USB connection | `usb 1-3` 04f2:b725 appears/disappears | present | absent |
| ~~Absolute firmware bit `CAMS`~~ | ~~`OperationRegion LFCN` @ phys `0xCCF7D333`~~ | **not a live state** - measured: stays 1 while the switch has the camera disconnected. Boot/config bit only; used by `HSP3._UPC`/`CAMA._STA` for ACPI enumeration. | - | - |

> **Verified end-to-end by physically moving the switch (2026-10-06):** the patched `ideapad-laptop` received the
> WMI events and emitted `SW_CAMERA_LENS_COVER` transitions (`70-evidence/camera-switch-trace.log`), and the camera
> dropped off USB each time (`usb 1-3: USB disconnect`). Linux therefore does *not* need a driver to know the
> state: the camera appearing/disappearing already carries it, and the WMI event (previously dropped by
> `ideapad-laptop`'s keymap) is available to any consumer. See `60-driver/README.md`.

EC mailbox value behind the event: **`LSKV`/`LSKD` = `0x0B` -> camera ON, `0x0C` -> camera OFF**
(phys `0xFE00D41F`, mapped to `_WED` ids `0x0C`/`0x0D`).

Windows additionally reads an absolute GPIO/camera byte from a **separate, unshipped** kernel driver
`\\.\EnergyDrv` (IOCTL `0x831020dc` bit7 = `CAMERA_BIT7` capability; IOCTL `0x831020c4` byte 0 = state), which is how
it decides which OSD icon to draw. That driver is not part of this package.

On Linux today: ACPI-WMI device `8FC0DE0C-…-28` **is** bound (`ideapad_wmi`, the "Legion 5" fn-key handler), so the
events already reach the kernel - but `ideapad-laptop.c`'s WMI keymap (`:1332-1366`) has **no entry for event ids
`0x0C`/`0x0D`**, so `ideapad_wmi_notify` -> `ideapad_input_report` -> `sparse_keymap_report_event()` drops them
silently (`40-kernel-src/ideapad-laptop.c:2316,1415-1419`). Nothing exposes the state or a
`SW_CAMERA_LENS_COVER` switch. The `CAMS` byte / `HSP3.CAMA._STA` / `HSP3._UPC` path is untouched by any loaded driver.

Full mechanism: **`20-acpi/analysis/05-camera-switch-mechanism.md`**.

---

## 2. What the package actually is

Inno Setup installer ("Modified by Lenovo") containing the UMDF/user-mode package
**"Lenovo Fn and function keys" v2.0.0.25 (2022-04-25)**.

- `lenovofnandfunctionkeys.inf`: `Class=System`, binds **`ACPI\LHK2019`**, `ServiceBinary=%13%\LenovoUtilityService.exe`.
- `ACPI\LHK2019` = `Device (HKDV)` in the DSDT (`DSDT.dsl:24668`) - an **empty device** (`_STA -> 0x0F`, no methods).
  Its only role is to make Windows install and keep alive the service.
- **No `.sys` kernel driver exists in the package** (catalogue `lenovofnandfunctionkeys.cat` lists payload only;
  signed by *Microsoft Windows Hardware Compatibility Publisher*).

Per-file roles: `10-extracted/analysis/WINDOWS-STACK.md`, `50-ghidra/lenovoutilityservice/REPORT.md`.

| File | Role (verified) |
|---|---|
| `LenovoUtilityService.exe` | service host. Watchdog on the `*LHK2019` PnP node (`SetupDi…`/`CM_Locate_DevNodeW`), launches the worker, mic-mute LED via WMI `ROOT\WMI:LENOVO_UTILITY_DATA::SetFeature(featuretype 1/2)`, capability probe `GetIfSupportOrVersion`. **No camera logic, no device path, no IOCTLs, no HID.** |
| `FnHotkeyUtility.exe` | **the interesting binary**: WMI event consumer (`SELECT * FROM LENOVO_UTILITY_EVENT`), OSD, camera decode, `\\.\EnergyDrv` GPIO access, DirectShow camera-privacy set, HID, refresh-rate control. |
| `mmstate.dll` | microphone-mute state tracking (`Enter/LeaveMicMuteStateTracking`, `GetState`) over `IAudioEndpointVolumeCallback`. |
| `BlurSwitchCS.dll` | .NET 4.6.1; class `BlurSwitchCS.ToggleBlurSwitch`, single method `Switch()` -> UWP AppService `Lenovo.CameraControlBackgroundService` in package `E0469640.SmartAppearance_5grkq8ppsgwt4`; `Key="ToggleBlurSwitch"`, reply `BlurOff/BlurOn/BlurError`. |
| `ControlLib.dll` / `IntelControlLib.dll` | Intel IGCL loader / per-GPU impl (86-87 `ctl*` exports). **Unrelated to the camera.** |
| `ludp.dll`, `ludp.net.dll` | Lenovo User Data Platform. No camera strings. |
| `atiadlxx.dll` | AMD ADL. Not used for the switch. |
| `dpinst.exe/xml`, `qrcode.*`, VC++ runtimes | installer plumbing. |

---

## 3. Reverse-engineering of `FnHotkeyUtility.exe` (the switch decode)

Ghidra 12.1.2 headless, full decompilation. The dump itself is not redistributed (§6); the symbol, string-xref
and vtable/RTTI listings that are included live in `50-ghidra/fnhotkeyutility/`. The `:NNNN` line references below
are offsets into the `decompile.txt` dump (5447 lines).

1. **Event subscription** - `CMoniterWmiUtilityEvent` (`FUN_140013800`) : `CoCreateInstance(CLSID_WbemLocator)` ->
   `ConnectServer(L"ROOT\\WMI")` -> `ExecNotificationQueryAsync(..., L"SELECT * FROM LENOVO_UTILITY_EVENT")`
   (`decompile.txt:708-800`). A second monitor `CMoniterWmiGetFnQ` handles the `FnQ` class.
2. **Raw-event dispatch** - `FUN_140020480` (`:5250`), trace string
   `"WMIMonitorMsgCenter g_UtilityEvent UtilityLSK2.0Status wParam=%d"`, guard `if (param_1 - 1U < 0x29)`,
   switch over the raw WMI event id `1..0x29`.
3. **Handler** - `MsgLogic::g_HandleEvent` = `FUN_14001aa60` (`:2344`, 8976 bytes), switch over the internal event id
   (`:2752`), valid `0..0x3a`.
4. **Camera switch cases** - `case 0x1e` -> OSD asset `0x7e1` + label `"CameraHW"`;
   `case 0x1f` -> OSD asset `0x7e2` + label `"CameraHW"` (`:3422-3442`). Names bound in the id table at
   `:4369`/`:4381` (`e_Event_CAMERA_SWITCH_ON`=0x1e, `e_Event_CAMERA_SWITCH_OFF`=0x1f).
   Raw ids that reach them: **`0x0C` (ON), `0x0D` (OFF)** (`:5353-5358`).
5. **Absolute state / capability** - `\\.\EnergyDrv` (`:1794`): IOCTL `0x831020dc` -> `out[0] >> 24` gives a
   **capability** mask (bit7 = `CAMERA_BIT7` = "camera OSD supported", `:2472-2504`). The camera *state* on the
   camera-key path comes from DirectShow `CameraPrivacy::SwitchCameraStatus` = `FUN_140007a90` @`0x140007a90`
   (`IAMCameraControl::Get(property 8)` over all capture devices, then `Set(..., !state, Flags=2)` = toggle);
   IOCTL `0x831020c4` (`:2932`) is only the fallback when that returns 0.
   **The hardware switch position itself is carried by the WMI event (§1/§2), not by this path.**
6. **Camera "privacy" toggle** - `IAMCameraControl::Set` over moniker-enumerated capture devices (`:41-132`) - a
   *write*, not a read of the hardware switch.

### Cross-validation of the mapping (the key result)

| EC `LSKV`/`LSKD` | DSDT `_WED` -> | Windows raw event | Windows handler | Meaning |
|---|---|---|---|---|
| `0x04` | `2` if `HKDB==0` else `3` | 2 / 3 | `e_Event_FNLK_ON` / `_OFF` | FnLock (also matches `_QDF`'s FnLock LED write at `:14836`) |
| **`0x0B`** | **`0x0C`** | **0x0C** | **`e_Event_CAMERA_SWITCH_ON`** | **switch ON** |
| **`0x0C`** | **`0x0D`** | **0x0D** | **`e_Event_CAMERA_SWITCH_OFF`** | **switch OFF** |

Two independent artifacts (ACPI `_WED` table and the binary's raw-event switch) agree, and the FnLock pair
independently validates that the raw event id space *is* `_WED`'s output space.

---

## 4. ACPI / firmware ground truth

Full details in `20-acpi/analysis/`:

- `01-event-chain.md` - `LSKV` -> `_QDF` -> `LSKD` -> `Notify(WMIU,0xD0)`/`Notify(GZFD,0xE8)`; complete `_WED`
  mapping; EC region field offsets; explicit statement that no AML writes `CAMS`.
- `02-lfcn-layout.md` - all 56 `LFCN` fields with offsets; `CAMS` at `0x19B` -> phys `0xCCF7D333`.
- `03-gzfd-wed.md` - the second `LSKD` consumer (`GZFD._WED` `0xE8` -> performance mode 0..3).
- `04-wmi-guid-map.md` - machine-generated decode of every `_WDG` on the system, with ObjectId/notify-id and the
  live bound driver.
- `05-camera-switch-mechanism.md` - the consolidated mechanism + everything ruled out.

Key namespaces: `WMIU` (PNP0C14, `_UID "LSK20"`, 3 GUIDs) and `GZFD` (PNP0C14, `_UID "GMZN"`, 23 GUIDs).

---

## 5. State of the Linux side (measured, not assumed)

- `8FC0DE0C-B4E4-43FD-B0F3-8871711C1294-28` -> bound to **`ideapad_wmi`**; `notify_id = D0`.
  `ideapad-laptop.c` comment: `/* Legion 5 */`. Its keymap has **no** entry for raw ids `0x0C`/`0x0D`
  (**the gap**).
- `50C76F1F-D8E4-D895-0A3D-62F4EA400013` (`lenovo_wmi_camera`, which would emit `SW_CAMERA_LENS_COVER`) is
  **absent** on this machine; module unloaded.
- `LHK2019:00` exists as an **unbound** platform device (the Windows INF's target).
- `ideapad_laptop`'s `camera_power` (VPC cmd `0x1D`/`0x1E`) reads `0` while the camera is enabled =>
  it is **not** the switch.
- No loaded driver reports any `SW_*` camera bit; `legion_laptop` (DKMS, unbound) contains **zero** camera code.
  See `40-kernel-src/analysis-legion-laptop.md`.
- Camera `04f2:b725` enumerates at USB `1-3` -> ACPI `\_SB.PCI0.GP17.XHC0.RHUB.HSP3` (`device:1c`), and
  `…HSP3.CAMA` (`device:1d`) is **present** => `CAMS == 1` right now.
- Prior art: no existing mainline/out-of-tree driver covers this; see `40-kernel-src/analysis-web-prior-art.md`.

---

## 6. What is in this repository

```
README.md                                  this report
STATE.md                                   running findings log (superseded by this report + 05-*)
tasks/*.md                                 subagent briefs
10-extracted/analysis/WINDOWS-STACK.md     full Windows architecture (verified with ilspycmd etc.)
10-extracted/analysis/DOTNET-SUMMARY.md
20-acpi/aml/*.aml, 20-acpi/dsl/*.dsl       raw + disassembled ACPI tables
20-acpi/analysis/01..05-*.md               ACPI/mechanism analysis (see §4; 05 is the answer)
20-acpi/mof/                               decoded WMI/BMOF class schema (+ DECODED.md)
40-kernel-src/*.c, analysis-*.md           upstream drivers + legion-laptop audit + web prior art
50-ghidra/scripts/*.java                   Ghidra scripts used
50-ghidra/fnhotkeyutility/                 REPORT.md, symbols, string xrefs, vtables
50-ghidra/lenovoutilityservice/            REPORT.md + symbol/import/string-xref listings
60-driver/                                 patched ideapad-laptop: patch, source, build/install scripts
60-driver/README.md                        what was changed, interfaces, verification
70-evidence/strings*.txt                   strings dumps for every payload binary
70-evidence/*.log                          live camera-switch + USB-presence traces (the end-to-end proof)
70-evidence/03-hardware-integrity-audit.md read-only proof + precise EC-read disclosure
70-evidence/acpi-event-chain-summary.txt   15-line summary
80-tools/*.c                               bmfdec/bmf2mof/bmfparse sources (Pali Rohar, GPL-2.0)
omp-archive-01a10fbd-.../                  the omp session: transcript, subagent logs, standalone viewer
```

### Not included (not redistributed)

Original Lenovo/Microsoft binaries are copyrighted and are **not** published here, and neither are full
decompilations of them. Everything below stays local; reproduce it from the installer with the tools in this repo.

| Excluded | Why |
|---|---|
| `00-input/01lf0aafar2w6jb0.exe` | Lenovo installer. sha256 `3e30c034e8a4cf310547d44fc663857607f7f365d1d5d8b80954b57c5bcf7b6d` |
| `10-extracted/…/source/*`, `dpinst.*` | unpacked Lenovo + Microsoft redistributable payloads |
| `10-extracted/analysis/blurswitchcs.decompiled.cs` | full decompiled vendor source |
| `50-ghidra/proj/` | Ghidra project databases (embed the vendor binaries) |
| `50-ghidra/**/decompile*.txt`, `vtables-decompile.txt`, `*-decomp.c` | full decompilation dumps |
| `60-driver/ideapad-camera/*.ko`, `*.o` | build artifacts; build from source instead |
| `80-tools/bmfdec`, `bmf2mof`, `bmfparse` | compiled binaries; `make` builds them from the included `.c` |

## 7. The Linux driver: implemented, tested, and then ruled out

The gap described in §5 was closed as an experiment: `ideapad-laptop` was extended to handle the `0x0C`/`0x0D`
events and to expose `SW_CAMERA_LENS_COVER` plus a read-only sysfs `camera_switch`
(`60-driver/ideapad-camera/0001-ideapad-laptop-report-camera-privacy-switch.patch`). It compiled clean, loaded,
and was driven by physically moving the switch.

| Observable | Result |
|---|---|
| `EV_SW SW_CAMERA_LENS_COVER` transitions | 12 transitions captured on toggle (`70-evidence/camera-switch-trace.log`) |
| camera on USB `1-3` | disappears/reappears on every toggle (`70-evidence/camera-presence.log`) |
| sysfs `camera_switch` (from `HSP3.CAMA._STA`) | **stayed `1` throughout** - so `CAMS` is not the live state |

**Conclusion: no new driver is needed.** Userspace can already tell the switch position from the camera appearing
and disappearing on USB, and the WMI event is available to any consumer once `ideapad-laptop`'s keymap knows the
ids. Adding a driver would duplicate state the system already exposes. The patch is kept as the working,
verified reference for anyone who wants the explicit `SW_CAMERA_LENS_COVER` interface or wants to upstream the
two keymap entries.

If it were to be upstreamed anyway, the shape would be: (1) add `0x0C`/`0x0D` to `ideapad-laptop`'s WMI keymap,
(2) expose `SW_CAMERA_LENS_COVER` (1 = covered/off), (3) drop the `CAMS`-based sysfs attribute since the
measurement disproved it as a state source. All paths are read-only, so the "no hardware writes" constraint holds.

## 8. Residual uncertainty

- The WMI event ids `0x0C`/`0x0D` are now captured live from a physical toggle of the switch (§7). The EC mailbox
  value behind them, `LSKV`/`LSKD` = `0x0B` -> ON and `0x0C` -> OFF, is still derived from two agreeing static
  tables (`_WED`'s output vs. the binary's raw-event switch) rather than a direct EC read.
- The exact WMI-class property carrying the event id into `FUN_140020480` is **confirmed** as
  `LENOVO_UTILITY_EVENT.PressTypeDataVal` (uint32, read-only `WMIEvent`) by decoding the firmware's own BMOF blob
  with the reference `bmfdec` implementation - see `20-acpi/mof/DECODED.md`.
- The BMOF/WMI class schema decode is **done and verified** (`20-acpi/mof/`); no class mentions "camera", so the
  event semantics above cannot be cross-checked against a class field name.

## 9. Licensing

The code in this repository is third-party GPL and is redistributed under its own terms:

| Component | License |
|---|---|
| `40-kernel-src/*.c`, `60-driver/ideapad-camera/` (incl. the patch) | `GPL-2.0-or-later` — Linux kernel sources, SPDX headers in each file |
| `80-tools/*.c` (`bmfdec`, `bmf2mof`, `bmfparse`) | `GPL-2.0` — (C) 2017 Pali Rohár, headers in each file |

`COPYING` carries the GPL-2.0 text those components require. The analysis documents, ACPI dumps, evidence and the
session archive are original work from the investigation, published as-is.
