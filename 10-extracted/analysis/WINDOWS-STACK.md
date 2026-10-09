# Windows package: "Lenovo Fn and function keys" v2.0.0.25 — verified stack

Task 09. Every factual claim below was produced by a real tool run in this workspace; the
raw, unedited output is reproduced in the **Evidence appendix** at the end (and in the
companion `blurswitchcs.decompiled.cs`). Nothing here is taken from the earlier unverified
scout notes. Items that are reasoned rather than directly observed are tagged `[INFERENCE]`.

**Tooling used** (all on this host, network available):
`dotnet 10.0.112` + `ilspycmd 11.1.0.9782` (ICSharpCode.Decompiler 11.1.0.9782, `dotnet tool
install -g ilspycmd`), GNU `file`, `sha256sum`, `openssl`, `grep`, `iconv`.
Hardware was not touched (this package is Windows-only; analysis is read-only).

---

## 1. Payload inventory — per-file role

Directory: `10-extracted/code$getextractpath$/source/` (literal `$` in the path).
The installer is a Lenovo-repacked Inno Setup package; the INF installs into `%13%`
(`\DriverStore`/`System32\drivers` target dir as resolved by `DefaultDestDir = 13`).

| File | Type (from `file`) | Role |
|---|---|---|
| `lenovofnandfunctionkeys.inf` | Windows setup INFormation | Binds ACPI device `LHK2019`, installs the auto-start service, copies the payload. |
| `lenovofnandfunctionkeys.cat` | DER PKCS#7 SignedData | WHCP catalogue covering the INF + payload. |
| `lenovoutilityservice.exe` | PE32+ x64 native **console** | The Windows service host (`LenovoFnAndFunctionKeys`). Launches the user-session worker. |
| `fnhotkeyutility.exe` | PE32+ x64 **.NET/C++/CLI GUI** | The user-session worker. Subscribes to WMI events and implements all hotkey/camera/blur logic. |
| `blurswitchcs.dll` | PE32 **i386 .NET Framework 4.6.1** | `BlurSwitchCS.ToggleBlurSwitch.Switch()` — WinRT AppService client that toggles software background blur. |
| `ludp.dll` | PE32+ x64 native | "LUDP Core" (Lenovo LUDP Windows SDK) — low-level Lenovo device/utility protocol. |
| `ludp.net.dll` | PE32+ x64 **.NET** (C++/CLI) | Managed wrapper over `ludp.dll`. |
| `mmstate.dll` | PE32+ x64 native | "Helper dll for mic mute indicator" — microphone mute LED/state helper (ProductName "Fn and function keys"). |
| `lenovo.assemblyvalidation.native.dll` | PE32+ x64 native | "Lenovo Assembly Validation Native" — validates the app's assemblies (anti-tamper). |
| `controllib.dll` | PE32+ x64 native | "Intel Graphics Control Lib Loader" — loads Intel IGCL / ControlAPI. |
| `intelcontrollib.dll` | PE32+ x64 native | "Intel Graphics Control Lib Runtime" — Intel GPU display settings. |
| `atiadlxx.dll` | PE32+ x64 native | AMD Display Library ("ADL Component"). |
| `msvcp140.dll`, `vcruntime140.dll`, `vcruntime140_1.dll` | PE32+ x64 native | Microsoft VC++ 2015–2022 runtime redistributables. |
| `system.runtime.windowsruntime.dll` | PE32 **i386 .NET** (Microsoft) | WinRT projection for .NET. **Present in the payload dir but NOT listed in the INF** (`SourceDisksFiles`/`HsaServcie_Files`); `[INFERENCE]` a stray/per-app copy, the .NET 4.6.1 assembly resolves `System.Runtime.WindowsRuntime` 4.0.0.0 from the GAC. |
| `qrcode.html`, `qrcode.png` | HTML / PNG | QR asset for Lenovo app pairing. |

**No `.sys` file exists anywhere in the package** (`find … -iname '*.sys'` → empty):
this is a pure user-mode/UMDF-style package, as stated in `STATE.md`.

---

## 2. Verified architecture chain (INF → service → worker → WMI → camera switch → UWP blur)

1. **ACPI device.** The INF matches `ACPI\LHK2019`. DSDT defines `Device (HKDV){ Name(_HID,"LHK2019") }`
   as an empty device (see `STATE.md`; DSDT.dsl:24670). The INF's only job is to bind that device so the
   driver store installs the service.

2. **Auto-start service.** From the decoded INF (Evidence A1):
   `AddService = LenovoFnAndFunctionKeys,0x00000800,LnvHsa_Service` with
   `StartType = SERVICE_AUTO_START (0x2)`, `ServiceType = SERVICE_OWN_PROCESS (0x10)`,
   `ServiceBinary = %13%\LenovoUtilityService.exe`. So Windows starts `LenovoUtilityService.exe`
   automatically once the device binds.

3. **Service launches the worker into the interactive session.** `lenovoutilityservice.exe` strings
   (Evidence C4) show `CUtilityService::ServiceWorkerThread LaunchFnHotkeyUtilityProcess`,
   `IsExistUtilityProcess The "%s" process is existance. Its session id is %u`,
   `WTSGetActiveConsoleSessionId()`, `CreateProcessInUserSession CreateProcessAsUser()`, and it reacts to
   `WTS_CONSOLE_CONNECT` / `WTS_CONSOLE_DISCONNECT`. i.e. the service spawns `FnHotkeyUtility.exe`
   inside the active console session (services cannot show OSD / WinRT UI from session 0).

4. **Worker subscribes to WMI events.** `fnhotkeyutility.exe` connects to the `ROOT\WMI` namespace
   (`Connected to ROOT\WMI WMI namespace`, Evidence C2) and issues two `ExecNotificationQueryAsync` WMI
   event subscriptions (Evidence C3, ASCII strings):
   `SELECT * FROM LENOVO_UTILITY_EVENT` and `SELECT * FROM LENOVO_GAMEZONE_SMART_FAN_MODE_EVENT`.
   Internally: `MoniterWmiUtilityEvent … Monitor LSKEvent button done.` and
   `MoniterWmiGetFnQ … FnQ Button press`.

5. **Camera-switch decode.** On a `LENOVO_UTILITY_EVENT` the handler reads the event blob and isolates a
   camera bit (Evidence C1):
   `MsgLogic g_HandleEvent m_bExistRFDevice&8`,
   `MsgLogic g_HandleEvent m_bExistRFDevice&8 pInfoData->Data[0] %d`,
   `MsgLogic g_HandleEvent SwitchCameraStatus  in ....`,
   `MsgLogic g_HandleEvent Init CAMERA_BIT7 fail!`, producing
   `e_Event_CAMERA_SWITCH_ON` / `e_Event_CAMERA_SWITCH_OFF`.
   `[INFERENCE]` firmware delivers the physical camera-switch state inside `pInfoData->Data[0]`; the exact
   bit/mask mapping (the string says `&8`, while another constant is named `CAMERA_BIT7`) is a per-model
   detail being pinned by the Ghidra disassembly peer, not by string inspection.

6. **Camera on/off action = Windows camera privacy.** `CameraPrivacy SwitchCameraStatus` enumerates video
   capture devices (`pMoniker[nIndexCamera]->BindToObject`, `QueryInterface`) and calls
   `pCameraControl[i]->Set` (Evidence C1) — i.e. DirectShow/`IAMCameraControl::Set` on each camera
   filter. This is the Windows-side software "camera privacy/shutter" toggle. `[INFERENCE]` the concrete
   property/flag being `Set` is fixed by the disassembly peer.

7. **Background-blur action = UWP AppService.** `e_Event_CAMERA_BG_BLUR` → `BlurSwitchCLR Switch retBlur=%d`
   → `BlurSwitchCS.ToggleBlurSwitch.Switch()` (the worker references assembly `BlurSwitchCS`, Evidence B5)
   → WinRT `AppServiceConnection`. `Switch()` sets
   `AppServiceName = "Lenovo.CameraControlBackgroundService"` and
   `PackageFamilyName = "E0469640.SmartAppearance_5grkq8ppsgwt4"`, sends
   `ValueSet{ "Key" = "ToggleBlurSwitch" }` and interprets the reply `Result` =
   `BlurOff` / `BlurOn` / `BlurError`. This is verified line-by-line in
   `blurswitchcs.decompiled.cs` and summarised in §3.

8. **UWP app activation (for the blur UI/settings app).** The worker also activates the Lenovo Utility UWP
   app: `E0469640.LenovoUtility_5grkq8ppsgwt4!LenovoUtility` via `ActivateApplication()`, and it knows the
   companion app family `E046963F.LenovoCompanion_k1h2ywk1493x8` (Evidence C5). The blur toggle's
   `LaunchSmartAppearance UWP` path and a `LENOVO_SMARTAPPEARANCE_DOWNLOAD_URL` suggest it can install/launch
   the SmartAppearance app if missing.

---

## 3. `blurswitchcs.dll` — verified .NET facts (ilspycmd)

Tool: `ilspycmd 11.1.0.9782`, input sha256 `4d6a09997bc5ae9b2bff05d40afd281645b6cd60e07647a7b03074c596c0b11f`.
Full unedited output is in `10-extracted/analysis/blurswitchcs.decompiled.cs`.

* **Identity:** assembly name `BlurSwitchCS`, version `1.0.0.0`, `TargetFramework .NETFramework v4.6.1`,
  GUID `a8bf1931-bcd8-4ccb-b8b6-b75b2f620041`, PE32 i386.
* **Types:** exactly two — `<Module>` and **`BlurSwitchCS.ToggleBlurSwitch`**.
  The task's suggested command `ilspycmd -t BlurSwitchCS` **fails** (`Could not find a type named
  'BlurSwitchCS'.`): `BlurSwitchCS` is the **namespace**, `ToggleBlurSwitch` is the **class**, and
  `Switch()` is the only method. (The earlier scout note that "class BlurSwitchCS has methods
  ToggleBlurSwitch/SendMessageAsync/OpenAsync" is therefore **refuted** — `SendMessageAsync`/`OpenAsync`
  are WinRT API calls made *inside* `Switch()`, not methods of the class.)
* **Status constants (exact names + values):**
  `STATUS_SET_BLUR_OFF_OK = 10000`, `STATUS_SET_BLUR_ON_OK = 10001`, `STATUS_SET_FEATURE_ERR = 10002`,
  `STATUS_RETURN_ERR = 10003`, `STATUS_EXCEPTION = 10005`, `STATUS_SET_TIMEOUT = 10006`,
  `STATUS_CONNECT_SVR_ERR = 10007`, `STATUS_SVR_REPOND_ERR = 10008` (the misspelling `REPOND` is in the
  binary).
* **Literals (exact):** `"Lenovo.CameraControlBackgroundService"`,
  `"E0469640.SmartAppearance_5grkq8ppsgwt4"`, `"Key"`, `"ToggleBlurSwitch"`, `"Result"`, `"BlurOff"`,
  `"BlurOn"`, `"BlurError"`. Connection Open timeout 5000 ms, message timeout 5000 ms.
* **AssemblyRefs:** `mscorlib 4.0.0.0`, `Windows.Foundation.UniversalApiContract 10.0.0.0`,
  `Windows.Foundation.FoundationContract 4.0.0.0`, `System.Runtime.WindowsRuntime 4.0.0.0`.

---

## 4. Signature & catalogue facts

* `lenovofnandfunctionkeys.cat` is DER-encoded PKCS#7 SignedData. Its signer is
  **`CN=Microsoft Windows Hardware Compatibility Publisher`**, issued by
  `CN=Microsoft Windows Third Party Component CA 2012`, which chains to
  `CN=Microsoft Root Certificate Authority 2010` (Evidence A4). This is the standard Windows Hardware
  Dev Center / WHCP attestation signature — the package passed Microsoft's hardware-certification signing.
* The catalogue is named by the INF (`CatalogFile=LenovoFnAndFunctionKeys.cat`), so the INF + listed
  payload files are covered by that signature.
* `[INFERENCE]` `system.runtime.windowsruntime.dll` is not listed in the INF and so is likely not covered
  by the catalogue; it appears to be a redundant per-app copy (see §1).

---

## 5. Does ANY component READ the camera-switch state?

**Answer: No component in this package independently reads/queries the camera-switch hardware.** The
package is *event-driven* and *write-only* with respect to the camera:

* **Input path (the only one):** the physical switch is delivered to userspace by firmware as a WMI event.
  `fnhotkeyutility.exe` subscribes to `LENOVO_UTILITY_EVENT` on `ROOT\WMI`
  (`70-evidence/strings-fnhotkeyutility.exe.txt:2872`) and decodes the switch state out of the event
  payload — `pInfoData->Data[0]` masked with `&8`
  (`70-evidence/strings16-fnhotkeyutility.exe.txt:904-905`) → `e_Event_CAMERA_SWITCH_ON/OFF`
  (`…:1000-1001`). It does **not** poll an EC byte, the ACPI `CAMS` bit, or `VPCCMD_R_CAMERA`.
* **Output paths (the only ones):**
  1. Windows camera privacy: `CameraPrivacy SwitchCameraStatus` → `IAMCameraControl::Set` per camera
     (`70-evidence/strings16-fnhotkeyutility.exe.txt:410-414`).
  2. Software background blur: `e_Event_CAMERA_BG_BLUR` → `BlurSwitchCLR Switch`
     (`…:1060`) → `BlurSwitchCS.ToggleBlurSwitch.Switch()` → UWP AppService
     `Lenovo.CameraControlBackgroundService` in `E0469640.SmartAppearance_5grkq8ppsgwt4`
     (`70-evidence/strings16-blurswitchcs.dll.txt:2-3`).
* The **hardware** lens/port gating is done by firmware via the ACPI `CAMS` bit (`STATE.md`, DSDT HSP3
  `_UPC`/CAMA `_STA`), which is outside this package entirely.
* The `\\.\EnergyDrv` kernel device used by `fnhotkeyutility.exe`
  (`70-evidence/strings16-fnhotkeyutility.exe.txt:439-464`) is an *external* Lenovo Energy-Management
  driver (not shipped here); its `GetDeviceStateCode`/GPIO/KBL calls concern keyboard backlight and
  smart-keyboard mode, not the camera switch.

Consequence for the Linux driver: the Windows package gives no reusable "read the switch" command — on
Linux the equivalent information must come from the firmware event path (ACPI `Notify(WMIU,0xD0)` /
`LSKD` via the `LENOVO_UTILITY_EVENT`-equivalent) or from the EC `CAMS` state, exactly as the other
subagents are mapping.

---

## Evidence appendix (verbatim tool output)

### A. INF & files

#### A1. `iconv -f UTF-16LE -t UTF-8 lenovofnandfunctionkeys.inf`
```
﻿;
; LenovoFnAndFunctionKeys.inf
;

[Version]
Signature="$Windows NT$"
Class = System
ClassGuid = {4d36e97d-e325-11ce-bfc1-08002be10318}
Provider=%ManufacturerName%
CatalogFile=LenovoFnAndFunctionKeys.cat
DriverVer = 04/25/2022,2.0.0.25

[Manufacturer]
%ManufacturerName%=Standard,NTamd64

[Standard.NTamd64]
%DeviceName%=LnvHsaDevice_Install, ACPI\LHK2019

[SourceDisksNames]
1 = %DiskName%

[SourceDisksFiles]
LenovoUtilityService.exe=1
Lenovo.AssemblyValidation.Native.dll=1
FnHotkeyUtility.exe=1
ludp.dll=1
ludp.net.dll=1
QRCode.html=1
QRCode.png=1
mmstate.dll=1
BlurSwitchCS.dll=1
msvcp140.dll=1
vcruntime140.dll=1
vcruntime140_1.dll=1
atiadlxx.dll=1
ControlLib.dll=1
IntelControlLib.dll=1

[DestinationDirs]
DefaultDestDir = 13
HsaServcie_Files = 13

[HsaServcie_Files]
LenovoUtilityService.exe,,,0x6
FnHotkeyUtility.exe,,,0x6
ludp.dll,,,0x6
ludp.net.dll,,,0x6
Lenovo.AssemblyValidation.Native.dll,,,0x6
QRCode.html,,,0x6
QRCode.png,,,0x6
mmstate.dll,,,0x6
BlurSwitchCS.dll,,,0x6
msvcp140.dll,,,0x6
vcruntime140.dll,,,0x6
vcruntime140_1.dll,,,0x6
atiadlxx.dll,,,0x6
IntelControlLib.dll,,,0x6
ControlLib.dll,,,0x6
; =================== UMDF Device ==================================

[LnvHsaDevice_Install.NT]
CopyFiles=HsaServcie_Files

[LnvHsaDevice_Install.NT.Services]
AddService = ,%SPSVCINST_ASSOCSERVICE%
AddService = LenovoFnAndFunctionKeys,0x00000800,LnvHsa_Service

[LnvHsa_Service]
DisplayName     = %ServiceName%
ServiceType     = %SERVICE_OWN_PROCESS%
StartType       = %SERVICE_AUTO_START%
ErrorControl    = %SERVICE_ERROR_IGNORE%
ServiceBinary   = %13%\LenovoUtilityService.exe
Description     = %ServiceDescription%

; =================== Generic ==================================

[Strings]
ManufacturerName="Lenovo"
ClassName="System"
DiskName = "Lenovo Fn and function keys Installation Disk"
DeviceName="Lenovo Fn and function keys"
ServiceName="Lenovo Fn and function keys service"
ServiceDescription="Lenovo Fn and function keys service"

SERVICE_BOOT_START      = 0x0
SERVICE_SYSTEM_START    = 0x1
SERVICE_AUTO_START      = 0x2
SERVICE_DEMAND_START    = 0x3
SERVICE_DISABLED        = 0x4
SERVICE_OWN_PROCESS     = 0x10
SERVICE_KERNEL_DRIVER   = 0x1
SERVICE_ERROR_IGNORE    = 0x0
SERVICE_ERROR_NORMAL    = 0x1
SERVICE_ERROR_SEVERE    = 0x2
SERVICE_ERROR_CRITICAL  = 0x3
SPSVCINST_ASSOCSERVICE  = 0x00000002
```

#### A2. `file *` (payload directory)
```
/home/user/Downloads/lenovo-camera-switch-re/10-extracted/code$getextractpath$/source/atiadlxx.dll:                         PE32+ executable for MS Windows 6.00 (DLL), x86-64, 7 sections
/home/user/Downloads/lenovo-camera-switch-re/10-extracted/code$getextractpath$/source/blurswitchcs.dll:                     PE32 executable for MS Windows 6.00 (DLL), Intel i386 Mono/.Net assembly, 3 sections
/home/user/Downloads/lenovo-camera-switch-re/10-extracted/code$getextractpath$/source/controllib.dll:                       PE32+ executable for MS Windows 6.00 (DLL), x86-64, 7 sections
/home/user/Downloads/lenovo-camera-switch-re/10-extracted/code$getextractpath$/source/fnhotkeyutility.exe:                  PE32+ executable for MS Windows 6.00 (GUI), x86-64 Mono/.Net assembly, 7 sections
/home/user/Downloads/lenovo-camera-switch-re/10-extracted/code$getextractpath$/source/intelcontrollib.dll:                  PE32+ executable for MS Windows 6.00 (DLL), x86-64, 7 sections
/home/user/Downloads/lenovo-camera-switch-re/10-extracted/code$getextractpath$/source/lenovo.assemblyvalidation.native.dll: PE32+ executable for MS Windows 6.00 (DLL), x86-64, 6 sections
/home/user/Downloads/lenovo-camera-switch-re/10-extracted/code$getextractpath$/source/lenovofnandfunctionkeys.cat:          DER Encoded PKCS#7 Signed Data
/home/user/Downloads/lenovo-camera-switch-re/10-extracted/code$getextractpath$/source/lenovofnandfunctionkeys.inf:          Windows setup INFormation
/home/user/Downloads/lenovo-camera-switch-re/10-extracted/code$getextractpath$/source/lenovoutilityservice.exe:             PE32+ executable for MS Windows 6.00 (console), x86-64, 7 sections
/home/user/Downloads/lenovo-camera-switch-re/10-extracted/code$getextractpath$/source/ludp.dll:                             PE32+ executable for MS Windows 6.00 (DLL), x86-64, 8 sections
/home/user/Downloads/lenovo-camera-switch-re/10-extracted/code$getextractpath$/source/ludp.net.dll:                         PE32+ executable for MS Windows 6.00 (DLL), x86-64 Mono/.Net assembly, 8 sections
/home/user/Downloads/lenovo-camera-switch-re/10-extracted/code$getextractpath$/source/mmstate.dll:                          PE32+ executable for MS Windows 6.00 (DLL), x86-64, 6 sections
/home/user/Downloads/lenovo-camera-switch-re/10-extracted/code$getextractpath$/source/msvcp140.dll:                         PE32+ executable for MS Windows 6.00 (DLL), x86-64, 7 sections
/home/user/Downloads/lenovo-camera-switch-re/10-extracted/code$getextractpath$/source/qrcode.html:                          HTML document, Unicode text, UTF-8 text, with CRLF line terminators
/home/user/Downloads/lenovo-camera-switch-re/10-extracted/code$getextractpath$/source/qrcode.png:                           PNG image data, 447 x 351, 8-bit/color RGBA, non-interlaced
/home/user/Downloads/lenovo-camera-switch-re/10-extracted/code$getextractpath$/source/system.runtime.windowsruntime.dll:    PE32 executable for MS Windows 6.00 (DLL), Intel i386 Mono/.Net assembly, 3 sections
/home/user/Downloads/lenovo-camera-switch-re/10-extracted/code$getextractpath$/source/vcruntime140.dll:                     PE32+ executable for MS Windows 6.00 (DLL), x86-64, 6 sections
/home/user/Downloads/lenovo-camera-switch-re/10-extracted/code$getextractpath$/source/vcruntime140_1.dll:                   PE32+ executable for MS Windows 6.00 (DLL), x86-64, 6 sections
```

#### A3. `sha256sum *` (payload directory)
```
21210831690c84b4bba08225fc0f1ac56f940e238701fda6e36020df96cb15f4  atiadlxx.dll
4d6a09997bc5ae9b2bff05d40afd281645b6cd60e07647a7b03074c596c0b11f  blurswitchcs.dll
cdb3b12b67590ad5cf3636cd37e8eb52269a50c2dabe9aa5e100df44ddba1ace  controllib.dll
d68d26b5805e138ee6b2dc8abba654ce7c9845b0b31b4c5385e62fe1785dc9d9  fnhotkeyutility.exe
b7a5066915648dc390e0478cef0ab1d6ad8e6efde11faeb37d2e69fbae219d68  intelcontrollib.dll
ad03ff8778c524d41806ee72833c7bdf1626b6ece9e146c78e5fc105a7c8a468  lenovo.assemblyvalidation.native.dll
32993c99c6245ec4f1b85f2bf1d81ee87474476578c964cc4c0afb451e5e8bd0  lenovofnandfunctionkeys.cat
df86be7e8eff01072252793fe5500c6b4ab19e132b08d71d5ee85769e8e28fae  lenovofnandfunctionkeys.inf
709827783ff089cdeafbb691c590289312a35b10eaa102da1e2f80964364bb26  lenovoutilityservice.exe
507f7e58a17fe0b920d31b04254cc506208d610f396e83dc99c3a2b10244c99f  ludp.dll
1363a2be340fda5b19426933a347f91455ca154d8571a07844afcd9f9faf23b3  ludp.net.dll
48440c3a866463472c5f64229a8fe491010c46d549abf5da6f27c068418acabe  mmstate.dll
701fc67d447cc89b97f5ae3e8d21ad97719a2cdc48de41fd55e9e46e42150303  msvcp140.dll
bebd7adbf1a7295113a52456afb56007e66b06541573337e9b99dca285dca238  qrcode.html
761d46fe3ad2ee267f4cbd736696d609de1d04c41699bc121f8f0cd8ff0aae4f  qrcode.png
b4125d24748a355ff44f682c8782d2e34849b9a97d65c7e4284471838bd751ad  system.runtime.windowsruntime.dll
b0d9507f44ce04069379d340d2a78caac0640b34d420066b4677d18674a591e1  vcruntime140.dll
6689bbff02f971de37f0f4e06f0bda8ecc59639251d287dd75f12165defbd463  vcruntime140_1.dll
```

#### A4. `openssl pkcs7 -inform DER -in lenovofnandfunctionkeys.cat -print_certs -noout`
```
subject=C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher
issuer=C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2012

subject=C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Third Party Component CA 2012
issuer=C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Root Certificate Authority 2010

```

#### A5. `find 10-extracted -iname "*.sys"`
```
(no output)
```

### B. `blurswitchcs.dll`
The complete, unedited ilspycmd output is the deliverable `blurswitchcs.decompiled.cs`. Extracts:

#### B1. `ilspycmd -t BlurSwitchCS "…/blurswitchcs.dll"`
```
Could not find a type named 'BlurSwitchCS'.
```

#### B2. `ilspycmd -l c "…/blurswitchcs.dll"`
```
Class <Module>
Class BlurSwitchCS.ToggleBlurSwitch
```

#### B3. Class shape (from `ilspycmd "…/blurswitchcs.dll"`)
```
namespace BlurSwitchCS;

public class ToggleBlurSwitch
{
	public const int STATUS_SET_BLUR_OFF_OK = 10000;
	public const int STATUS_SET_BLUR_ON_OK = 10001;
	public const int STATUS_SET_FEATURE_ERR = 10002;
	public const int STATUS_RETURN_ERR = 10003;
	public const int STATUS_EXCEPTION = 10005;
	public const int STATUS_SET_TIMEOUT = 10006;
	public const int STATUS_CONNECT_SVR_ERR = 10007;
	public const int STATUS_SVR_REPOND_ERR = 10008;

	public static int Switch()
```

#### B4. IL constant pool (`ilspycmd -t BlurSwitchCS.ToggleBlurSwitch -il "…/blurswitchcs.dll"`)
```
	IL_0007: ldstr "Lenovo.CameraControlBackgroundService"
	IL_0012: ldstr "E0469640.SmartAppearance_5grkq8ppsgwt4"
	IL_0029: ldc.i4 5000
	IL_0035: ldc.i4 10006
	IL_0049: ldc.i4 10007
	IL_005c: ldstr "Key"
	IL_0061: ldstr "ToggleBlurSwitch"
```
(reply parsing maps string `"Result"` → `"BlurOff"`=10000 / `"BlurOn"`=10001 / `"BlurError"`=10002 /
other=10003; see the full IL in the companion file.)

### C. `fnhotkeyutility.exe` / `lenovoutilityservice.exe` strings (grep over `70-evidence/`)
#### C1. Camera-switch decode & camera privacy
```
410:CameraPrivacy SwitchCameraStatus CoCreateInstance Line: %d  GetLastError: %d
411:CameraPrivacy SwitchCameraStatus pMoniker[nIndexCamera]->BindToObject Line: %d  GetLastError: %d
412:CameraPrivacy SwitchCameraStatus QueryInterface Line: %d  GetLastError: %d
413:CameraPrivacy SwitchCameraStatus pCameraControl[i]->Set Line: %d  GetLastError: %d
414:CameraPrivacy SwitchCameraStatus out
892:MsgLogic g_HandleEvent Init CAMERA_BIT7 fail! Line: %d  GetLastError: %d
901:MsgLogic g_HandleEvent m_OsdSupport CAMERA_BIT7  TRUE
902:MsgLogic g_HandleEvent SwitchCameraStatus  in ....
904:MsgLogic g_HandleEvent m_bExistRFDevice&8
905:MsgLogic g_HandleEvent m_bExistRFDevice&8 pInfoData->Data[0] %d
977:e_Event_Carema_Utility
1000:e_Event_CAMERA_SWITCH_ON
1001:e_Event_CAMERA_SWITCH_OFF
1027:e_Event_CAMERA_BG_BLUR
1060:e_Event_CAMERA_BG_BLUR BlurSwitchCLR Switch retBlur=%d
1062:e_Event_CAMERA_BG_BLUR LaunchSmartAppearance UWP success 
1063:e_Event_CAMERA_BG_BLUR LaunchSmartAppearance UWP failed =%d
1064:MsgLogic e_Event_CAMERA_BG_BLUR strLVFComponentInstallPath RegKeyExists Line: %d  GetLastError: %d
1065:MsgLogic  e_Event_CAMERA_BG_BLUR try catch Line: %d  GetLastError: %d
1083:MsgLogic e_Event_CAMERA_BG_BLUR Launch lenovo-smartappearance failed! Line: %d GetLastError: %d
1085:e_Event_CAMERA_BG_BLUR ShellExecuteEx LENOVO_SMARTAPPEARANCE_DOWNLOAD_URL fail =  %d
```
#### C2. WMI connection / monitoring
```
470:Connected to ROOT\WMI WMI namespace
479:ROOT\WMI
655:MoniterWmiGetFnQ Indicate FnQ Button press(%d),(%d)_
656:MoniterWmiGetFnQ Indicate FnQ Button press(%d)_  Line: %d GetLastError: %d
663:MoniterWmiGetFnQ _Thread_WmiFnQMonitor ConnectServer to ROOT\WMI WMI namespace
667:MoniterWmiGetFnQ _Thread_WmiFnQMonitor ExecNotificationQueryAsync Line: %d  GetLastError : %d
671:MoniterWmiUtilityEvent StartUtilityEventMonitor Monitor LSKEvent button done.
675:MoniterWmiUtilityEvent _Thread_WmiUtilityEventMonitor Connected to ROOT\WMI WMI namespace
679:MoniterWmiUtilityEvent _Thread_WmiUtilityEventMonitor ExecNotificationQueryAsync Line: %d  GetLastError: %d
```
#### C3. WMI event queries (ASCII strings)
```
2871:SELECT * FROM LENOVO_GAMEZONE_SMART_FAN_MODE_EVENT
2872:SELECT * FROM LENOVO_UTILITY_EVENT
```
#### C4. Service → user-session worker
```
412::CUtilityService::ServiceWorkerThread LaunchFnHotkeyUtilityProcess return success
413::CUtilityService::ServiceWorkerThread LaunchFnHotkeyUtilityProcess return fail, error: %d
420:FnHotkeyUtility.exe
424:GetCurrentUserNameAndSessionId WTSGetActiveConsoleSessionId() return fail, error: 0x%x
426:CreateProcessInUserSession CreateProcessAsUser() return fail, error: %d
440:::UtilityPackageCheckDelayTimerCallback LaunchFnHotkeyUtilityProcess sucess
441:::UtilityPackageCheckDelayTimerCallback LaunchFnHotkeyUtilityProcess fail
444:::OnServiceControlHandle User Session WTS_CONSOLE_CONNECT
473::CUtilityService::OnServiceControlHandle LaunchFnHotkeyUtilityProcess return fail, error: %d
```
#### C5. Which binary contains which package-family string
```
/home/user/Downloads/lenovo-camera-switch-re/70-evidence/strings16-fnhotkeyutility.exe.txt:649:E0469640.LenovoUtility_5grkq8ppsgwt4
/home/user/Downloads/lenovo-camera-switch-re/70-evidence/strings16-fnhotkeyutility.exe.txt:832:E046963F.LenovoCompanion_k1h2ywk1493x8
/home/user/Downloads/lenovo-camera-switch-re/70-evidence/strings16-fnhotkeyutility.exe.txt:854:E0469640.LenovoUtility_5grkq8ppsgwt4!LenovoUtility
/home/user/Downloads/lenovo-camera-switch-re/70-evidence/strings16-fnhotkeyutility.exe.txt:1081:E0469640.SmartAppearance_5grkq8ppsgwt4
/home/user/Downloads/lenovo-camera-switch-re/70-evidence/strings16-blurswitchcs.dll.txt:2:Lenovo.CameraControlBackgroundService
/home/user/Downloads/lenovo-camera-switch-re/70-evidence/strings16-blurswitchcs.dll.txt:3:E0469640.SmartAppearance_5grkq8ppsgwt4
```
Interpretation: `E0469640.LenovoUtility_5grkq8ppsgwt4` and
`E0469640.LenovoUtility_5grkq8ppsgwt4!LenovoUtility` and `E046963F.LenovoCompanion_k1h2ywk1493x8` occur
**only in `fnhotkeyutility.exe`**; `Lenovo.CameraControlBackgroundService` occurs **only in
`blurswitchcs.dll`**. Both binaries mention `E0469640.SmartAppearance_5grkq8ppsgwt4`.

### D. `blurswitchcs.dll` .NET identity (ilspycmd metadata tables)
Dumps are reproduced in full in `blurswitchcs.decompiled.cs` (commands 5 and 6):
```
Assembly: BlurSwitchCS 1.0.0.0, SHA1, no strong-name public key
AssemblyRef: mscorlib 4.0.0.0 / Windows.Foundation.UniversalApiContract 10.0.0.0 /
             Windows.Foundation.FoundationContract 4.0.0.0 / System.Runtime.WindowsRuntime 4.0.0.0
```
