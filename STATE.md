> **SUPERSEDED** - this was the running findings log during the investigation. The authoritative result is
> `README.md` (master report) and `20-acpi/analysis/05-camera-switch-mechanism.md` (the mechanism).
> Corrections made after this file was written: the state source is the WMI event `PressTypeDataVal` (12/13), not
> `\\.\EnergyDrv` IOCTL `0x831020c4` (that is only a fallback); `IOCTL 0x831020dc` is a capability mask. The BMOF
> blobs are **not** encrypted (BMF + DS-01) and have been decoded - see `20-acpi/mof/DECODED.md`.

# Reverse-engineering: Lenovo camera toggle switch (82JU) → Linux driver

Target: `/home/user/Downloads/01lf0aafar2w6jb0.exe`
sha256: `3e30c034e8a4cf310547d44fc663857607f7f365d1d5d8b80954b57c5bcf7b6d` (PE32 i386, Inno Setup "Modified by Lenovo")
Unpacked payload: **"Lenovo Fn and function keys"** v2.0.0.25 (2022-04-25), UMDF/user-mode package (no .sys kernel driver).

## Machine under test
- Lenovo Legion 5 15ACH6H, product `82JU`, BIOS `GKCN65WW` 1.65, DMI board `LNVNB161216`.
- Kernel `7.2.7-arch1-1` (Arch). Full kernel build tree at `/usr/src/linux` (**stripped: no .c files**), `vmlinux`, `System.map`.
- Camera: USB `04f2:b725` Chicony "Integrated Camera" (bus 1, port 4) — **currently enumerated**.
- ITE HID: `048d:c965` "ITE Device(8295)" (3-3), `048d:c101` "ITE Device(8910)" (1-4), both keyboard/HID + rfkill.
- Root access: no sudo password. **docker works** → use `docker run --privileged -v ... debian:stable-slim` for root-only ops (ACPI tables, /dev/mem, insmod).

## What the Windows driver actually is
`lenovofnandfunctionkeys.inf`:
```
Class = System ; DriverVer 04/25/2022,2.0.0.25
[Standard.NTamd64]  %DeviceName%=LnvHsaDevice_Install, ACPI\LHK2019
[LnvHsaDevice_Install.NT.Services] AddService = LenovoFnAndFunctionKeys,...,ServiceBinary=%13%\LenovoUtilityService.exe
```
- Binds ACPI device **`LHK2019`** = `Device (HKDV)` in DSDT (DSDT.dsl:24668) → **empty device**, only `_STA → 0x0F`. No methods.
- So the INF's job is only to install/start the user-mode service when that device exists. All logic is user-mode.
- Payload: `LenovoUtilityService.exe` (service), `FnHotkeyUtility.exe` (worker: OSD/WMI events), `ludp.dll`, `mmstate.dll` (mic-mute tracking), `BlurSwitchCS.dll` (.NET, `ToggleBlurSwitch` → calls **UWP AppService** `E0469640.LenovoUtility_5grkq8ppsgwt4!LenovoUtility`), `ControlLib.dll`, `Intel/AMDControlLib.dll`, `atiadlxx.dll`.

### Windows event source (from `strings` of fnhotkeyutility.exe)
- `SELECT * FROM LENOVO_UTILITY_EVENT` and `SELECT * FROM LENOVO_GAMEZONE_SMART_FAN_MODE_EVENT` on namespace `ROOT\WMI`.
- Classes: `CMoniterWmiUtilityEvent` ("Monitor LSKEvent button done"), `CMoniterWmiGetFnQ` ("FnQ Button press").
- Strings: `MsgLogic g_HandleEvent Init CAMERA_BIT7 fail!`, `MsgLogic g_HandleEvent SwitchCameraStatus in ....`,
  `MsgLogic e_Event_CAMERA_BG_BLUR ...`, `e_Event_FnQ`, `e_Event_FnQ_X60`.
- Mic-mute LED via HID `LSK_SetFeature` (see `lenovo-wmi-hotkey-utilities.c` upstream).

## Linux side — current state (nothing reports the switch today)
WMI GUID → driver (modalias `wmi:<GUID>`):

| GUID | module | present on 82JU? |
|---|---|---|
| `8FC0DE0C-B4E4-43FD-B0F3-8871711C1294` | `ideapad_laptop` (`ideapad_wmi`, comment `/* Legion 5 */`) | **YES**, bound, notify_id `0xD0` |
| `CE6C0974-0407-4F50-88BA-4FC3B6559AD8` | `lenovo_wmi_hotkey_utilities` (LUD mic/audio mute LED) | YES, bound |
| `D320289E-8FEA-41E0-86F9-911D83151B5F` | `lenovo_wmi_events` (thermal) | YES, bound |
| `887B54E3-DDDC-4B2C-8B88-68A26A8835D0` | `lenovo_wmi_gamezone` | YES, bound |
| `DC2A8805-3A8C-41BA-A6F7-092E0089CD3B` | `lenovo_wmi_other` | YES, bound |
| `50C76F1F-D8E4-D895-0A3D-62F4EA400013` | `lenovo_wmi_camera` (**would emit `SW_CAMERA_LENS_COVER`**) | **NO — absent** |

- `ideapad_laptop` is live: `/sys/devices/pci0000:00/0000:00:14.3/PNP0C09:00/VPC2004:00/` with
  `camera_power` (**reads 0**), `fn_lock`, `conservation_mode`, `fan_mode`, `usb_charging`, input "Ideapad extra buttons" (**sw=0**, no switch bits).
- `VPCCMD_R_CAMERA = 0x1D`, `VPCCMD_W_CAMERA = 0x1E` (VPC EC command, upstream `ideapad-laptop.c`).
- `LHK2019:00` **platform device exists and is UNBOUND** (hence the Windows INF target has no Linux driver).
- No input device on the system reports any `SW_*` camera bit. Nothing exposes the switch.

## ACPI ground truth (tables dumped via docker)
`20-acpi/aml/*.aml` = raw tables, `20-acpi/dsl/*.dsl` = `iasl -d` output.
- DSDT:11645 `Device (EC0)` `PNP0C09`, `_GPE = 0x03`, `OperationRegion (ERAM, EmbeddedControl, 0, 0xFF)` with `Field{ VCMD }`,
  `ECB2 = SystemMemory 0xFF00D520`, `ERAX = SystemMemory 0xFE00D400` (`VDAT`,`VSTA`,`FANS`,...), `ECMS = IO 0x72`, `CMDE = IO 0x62`.
- DSDT:13785 `Scope(\)`: `OperationRegion (LFCN, SystemMemory, 0xCCF7D198, 0x01FE)` with field **`CAMS, 8`** (offset 0x... see analysis).
- DSDT:6744 `_UPC` of `HSP3` returns port-enabled iff `CAMS`, else `{0,0,0,0}`; DSDT:6830 `Device (CAMA)._STA` returns 0x0F iff `CAMS`.
  ⇒ **`CAMS` is the camera-privacy firmware bit; it gates the USB camera port.**
- DSDT:24670 `Device (HKDV){ Name(_HID,"LHK2019"), _UID 0 }` — empty (Windows INF target).
- DSDT:24676 `Device (WMIU){ _HID PNP0C14, _UID "LSK20", _WDG(0x3C) → GUIDs
  CE6C0974-0407-4F50-88BA-4FC3B6559AD8, 8FC0DE0C-B4E4-43FD-B0F3-8871711C1294, 05901221-D566-11D1-B2F0-00A0C9062910 }`, with
  `Method(_WED,1)` handling `Arg0 == 0xD0` and mapping **`LSKD`** → event value; `Method(WMSK,3)` (firmware-marker).
- DSDT:14851 `Notify (WMIU, 0xD0)` — the event trigger. DSDT:14823 `Name (LSKD, Zero)`; DSDT:14833 `LSKD = LSKV`.
- EC RAM names seen: `LSKV`, `LSKD`. WMIU `_WED` returns ints derived from `LSKD` (1,2,3,4/5,6,… see full table).
- SSDT3:2690 `Name (WQBA, Buffer (0x0A57))` starting `46 4F 4D 42 01 00 00 00` = `"FOMB"`+v1+len 0x0A47 → **BMOF/binary-MOF blob** (magic byte order needs explanation; see analysis).

## Upstream Linux sources fetched → `40-kernel-src/`
- `ideapad-laptop.c` (2574 lines) — `+2` keymap `{KE_KEY,7,{KEY_CAMERA}}`, WMI `0x28`→`KEY_PROG3` "Lenovo Virtual Background application",
  `ideapad_wmi_context_fn_keys` for `8FC0DE0C` (Legion 5), `camera_power` sysfs via `VPCCMD_R_CAMERA`.
- `wmi-camera.c` — GUID `50C76F1F…`, `input_report_switch(SW_CAMERA_LENS_COVER)`, `1 == lens open`.
- `wmi-hotkey-utilities.c`, `wmi-events.c` — LUD LEDs, notifier chain.

## Goal
Linux driver that (a) reports camera-switch state to userspace, (b) tracks switch movement on this exact machine,
ideally `SW_CAMERA_LENS_COVER` on an input device + a readable sysfs value.

## Open questions (assigned to subagents)
1. Exact `LSKV`/`LSKD` EC byte offsets + full `_WED` LSKD→value table; which value = camera switch.
2. What the Windows binaries do with the event: `CAMERA_BIT7`, `SwitchCameraStatus` — which bit/byte and which WMI class field.
3. Authoritative state source for the *current* switch position (CAMS bit? EC byte? VPC cmd 0x1D? WMI query?).
4. Whether toggle produces an ACPI/WMI notify Linux can consume, and which GUID/notify id.
5. Why `camera_power` reads 0 while the camera is enumerated (polarity/validity of VPC 0x1D on this model).

## Tooling
- Ghidra 12.1.2 `/opt/ghidra/support/analyzeHeadless`, JDK 27. `dotnet` available (ilspycmd installable) for the .NET DLL.
- `python3` + `pefile`. No radare2/binwalk/7z. `innoextract` only inside docker (debian).
- Docker debian:stable-slim has net; used for root ops + acpica/innoextract.
