# 05 - Camera toggle switch: complete mechanism (RE result)

Cross-validated between (a) the ACPI firmware decode of `_WED` and (b) the raw-event dispatch table in
`FnHotkeyUtility.exe`. Both sides agree; this is the authoritative answer.

## 1. The switch transition is a firmware WMI event

Chain (all citations `20-acpi/dsl/DSDT.dsl`):

1. The EC writes event id `LSKV` (EC window `ERAX`, SystemMemory `0xFE00D400`, byte offset `0x1F` -> phys `0xFE00D41F`; `:11701,11702,11766`).
2. EC query `_QDF` (`:14826`) fires: if `0 < LSKV < 0x27` then `LSKD = LSKV` (`:14831-14833`), `LSKV = 0` (`:14848`).
3. `_QDF` then issues `Notify (WMIU, 0xD0)` and `Notify (GZFD, 0xE8)` (`:14851-14852`).
4. `WMIU` is `PNP0C14` `_UID "LSK20"`; its `_WDG` entry 2 is GUID `8FC0DE0C-B4E4-43FD-B0F3-8871711C1294`
   with ObjectId `0x00D0` (= the notify id) (`:24678-24690`, decode in `04-wmi-guid-map.md`).
5. `WMIU._WED(0xD0)` maps `LSKD` -> the integer WMI event id (`:24771-24929`).

## 2. `_WED` -> raw WMI event id (from the DSDT) and what Windows does with it

`FnHotkeyUtility.exe` subscribes to `SELECT * FROM LENOVO_UTILITY_EVENT` in `ROOT\WMI` and dispatches on the
**raw WMI event id** in `FUN_140020480` (`50-ghidra/fnhotkeyutility/decompile.txt:5250`), whose own trace string is
`"WMIMonitorMsgCenter g_UtilityEvent UtilityLSK2.0Status wParam=%d"` and whose guard is `if (param_1 - 1U < 0x29)`
(range 1..0x29 - matching `_WED`'s output range exactly).

| EC `LSKV`/`LSKD` | `_WED` result (raw WMI event id) | Windows dispatch | Meaning |
|---|---|---|---|
| `0x01` | 1 | `FUN_140020480` case 1 -> default | (favourites/star key) |
| `0x02` | 5 | case 5 -> 0x15 | |
| `0x03` | 6 | case 6 -> 0x16 | |
| `0x04` | 2 if `HKDB==0` else 3 | case 2 -> 0x1a / case 3 -> 0x1b | **FnLock** toggle (matches `_QDF`'s `LSKD==0x04` FnLock LED write, `:14836-14846`) |
| `0x05` | 4 | case 4 -> 0x19 | camera key |
| **`0x0B`** | **0x0C** | **case 0x0c -> 0x1e = `e_Event_CAMERA_SWITCH_ON`** | **camera switch -> ON** |
| **`0x0C`** | **0x0D** | **case 0x0d -> 0x1f = `e_Event_CAMERA_SWITCH_OFF`** | **camera switch -> OFF** |
| ... | ... | ... | |
| `0x25` | 0x26 | case 0x26 -> 0x2b | |

`e_Event_CAMERA_SWITCH_ON` / `_OFF` are enum values **0x1e / 0x1f**, explicitly built by name in the event table
(`decompile.txt:4369,4381`) and each is a `case` in `MsgLogic::g_HandleEvent` = `FUN_14001aa60`
(`decompile.txt:2344`, switch at `:2752`):

```c
case 0x1e:                       /* e_Event_CAMERA_SWITCH_ON */
    FUN_1400184a0(0x7e1, ...);   /* OSD asset = camera ON  */
    puVar19 = &DAT_140039f58;
    goto LAB_14001c5af;          /* label "CameraHW"       */
case 0x1f:                       /* e_Event_CAMERA_SWITCH_OFF */
    FUN_1400184a0(0x7e2, ...);   /* OSD asset = camera OFF */
    puVar19 = &DAT_140039f98;
LAB_14001c5af:
    pwVar39 = L"CameraHW";       /* decompile.txt:3419-3442 */
```

**Conclusion: `LSKV`/`LSKD` = `0x0B` means "camera switch ON", `0x0C` means "camera switch OFF", delivered as WMI
event ids `0x0C` / `0x0D` on WMI GUID `8FC0DE0C-B4E4-43FD-B0F3-8871711C1294`, notify `0xD0`.**

## 3. The absolute state / capability comes from a separate kernel driver `\\.\EnergyDrv`

`FnHotkeyUtility.exe` opens `CreateFileW(L"\\\\.\\EnergyDrv", 0xc0000000 /*GENERIC_READ|WRITE*/, 3, ...)`
(`decompile.txt:1794`) - the Lenovo "Energy Management" driver, **not shipped in this package**.
It is used through a DeviceIoControl wrapper `FUN_140008a80(hDevice, ioctl, in, inLen, out, outLen)`.

Init (`MsgLogic g_HandleEvent Init`, `decompile.txt:2456-2504`):

```c
DeviceIoControl(h, 0x831020dc, NULL, 0, local_fb88, 4, ...);   /* "GetGpioInfo", decompile.txt:2472 */
DAT_1400560fc = local_fb88[0] >> 0x18;                          /* TOP BYTE of the DWORD */
bVar48 = -1 < (char)DAT_1400560fc;                              /* = bit7 of that byte */
if (bVar48) log("Init CAMERA_BIT7 fail!");                      /* decompile.txt:2484 */
DAT_140056148 = !bVar48;                                        /* camera OSD supported */
/* same byte: 0x40 -> TOUCHPAD_BIT6 (:2490), 0x20 -> MIC_BIT5 (:2496), 0x08 -> NUMLK_BIT3 (:2502) */
```

Second read into `DAT_140056160` (`= (byte)(local_fbbc >> 0x10)`, `:2515-2520`).

On the camera key event (`case 4` = `e_Event_Camera`, `decompile.txt:2905-2949`):

```c
uVar20 = FUN_140007a90((int *)(local_fc00 + 9));        /* decompile.txt:2907  CameraPrivacy::SwitchCameraStatus */
if ((int)uVar20 != 0) {                                 /* -> "SwitchCameraStatus in ...." (:2909) */
    if (local_fbb8[0] == 0) asset = 0x7e2; else asset = 0x7e1;   /* :2910-2912 */
}
/* only if that returns 0: */
if ((DAT_140056160 & 8) != 0) {                         /* :2926 */
    FUN_140008a80(0xc, 0x831020c4, pIVar24, 4, pIVar1, 4);       /* :2932  fallback IOCTL  */
    asset = (pIVar1->Data[0] == 1) ? 0x7e1 : 0x7e2;              /* :2938-2941 */
}
```

**Correction (previously mis-stated):** `IOCTL 0x831020dc` returns a **capability** mask, not the state
(`DAT_1400560fc = out[0] >> 24`; bit7 -> `CAMERA_BIT7` = "camera OSD supported" -> `DAT_140056148`; bit6/bit5/bit3 ->
touchpad/mic/numlk; on failure the constant `0xF8` is forced, `:2465`).

The **state** on the camera-key path comes from `CameraPrivacy::SwitchCameraStatus` = `FUN_140007a90` @`0x140007a90`,
which uses **DirectShow**, not the EC: `CLSID_SystemDeviceEnum` -> `CLSID_VideoInputDeviceCategory` ->
`IMoniker::BindToObject(IBaseFilter)` -> `QI IID_IAMCameraControl` -> `Get(property = 8, &val, &flags)` on every
capture device; `state = 1` iff no camera reports 0; then `Set(property = 8, !state, CameraControl_Flags_Manual)`,
i.e. **it toggles the Windows camera-privacy property** (`IAMCameraControl` vtable verified from `strmif.h`:
`Set = +0x20`, `Get = +0x28`; property index 8 is outside the documented 0..6 range -> vendor/UVC privacy control
[INFERENCE]). The OSD shows the pre-toggle value.

`IOCTL 0x831020c4` (in dword 7, out `Data[0]`; `1` -> asset `0x7e1` else `0x7e2`) is only the **fallback** used when
`SwitchCameraStatus` returns 0 and the GPIO byte has bit3 set. IOCTL IDs: `0x831020dc` (capability / "GetGpioInfo"),
`0x831020c4` ("GetSmartKeyBoardEventMode", `decompile.txt:272,278`), `0x831020e0` (notify registration, `:1824`).

Separately, `e_Event_Camera` (id 4) is itself produced **only** by bit 7 (`0x80`) of the `\\.\EnergyDrv` *notify*
DWORD delivered to `FUN_140008fd0` @`0x140008fd0` (the notify thread registered at `:1824`), i.e. the EnergyDrv
notify path signals "camera key pressed", while the WMI event path carries the switch position.

## 4. Firmware `CAMS` bit - boot/config, **not** the live state

> **CORRECTION (measured 2026-10-06, after physically moving the switch on 82JU).** `CAMS` does **not** track the
> switch: with the switch engaged (camera gone from USB) the ACPI `_STA` of `HSP3.CAMA` still returned `0x0f`, i.e.
> `CAMS` stayed 1 through repeated toggles. It only says whether the camera port is enabled for ACPI enumeration
> (an EC/firmware configuration bit). The live signals are the **WMI event** (S2) and the camera's **USB presence**
> - both confirmed working. The ACPI plumbing below is accurate; only the earlier "absolute state" reading of it
> was wrong.

Independent of the WMI event stream, the firmware also keeps this bit:

- `CAMS` (8-bit) is byte `0x19B` of `OperationRegion (LFCN, SystemMemory, 0xCCF7D198, 0x01FE)` (`:13785,13826`)
  -> **physical `0xCCF7D333`**, inside the BIOS-reserved range `c9f7f000-ccf7efff` (`/proc/iomem`).
- `CAMS` gates the camera's USB port: `HSP3._UPC` returns port-enabled iff `CAMS` (`:6744`), and
  `Device (CAMA)._STA` returns `0x0F` iff `CAMS` (`:6830`).
- The camera (`04f2:b725`) enumerates under `\_SB.PCI0.GP17.XHC0.RHUB.HSP3` (verified: USB `1-3` ->
  `/sys/bus/acpi/devices/device:1c` = `...RHUB.HSP3`; `device:1d` = `...HSP3.CAMA` **present**).
- No AML ever writes `CAMS` (`20-acpi/analysis/01-event-chain.md`); the EC/firmware owns it.
- **Observed: `CAMA` device node present => `CAMS == 1`**, and it stayed 1 while the switch had the camera
  disconnected (see the correction above) - so it cannot be used to read the switch.

## 5. What is *not* the switch (ruled out)

| Candidate | Verdict | Evidence |
|---|---|---|
| `ACPI\LHK2019` device (`Device (HKDV)`) | Not a state source - empty device, no methods | `DSDT.dsl:24668`; `50-ghidra/lenovoutilityservice/REPORT.md` §2.1 |
| `ideapad_laptop` `camera_power` (VPC EC cmd `0x1D`) | Reads `0` while the camera is enabled -> **not** the switch; it is a separate IdeaPad VPC camera-power control | live read; `40-kernel-src/ideapad-laptop.c:585` |
| `lenovo_wmi_camera` (`SW_CAMERA_LENS_COVER`) | GUID `50C76F1F-…` **absent** on 82JU, module unloaded | `modinfo`, `/sys/bus/wmi/devices` |
| WMI event GUI id on a *separate* device | `Notify(GZFD,0xE8)` carries only performance-mode 0..3 derived from the same `LSKD` | `DSDT.dsl:22140-22189` |
| `BlurSwitchCS` / `e_Event_CAMERA_BG_BLUR` | Software background blur via UWP AppService, not the switch | `10-extracted/analysis/blurswitchcs.decompiled.cs` |
| `IamCameraControl::Set` ("CameraPrivacy") | Windows-side camera privacy *set*, not a hardware read | `decompile.txt:41-132` |

## 6. Toolchain / evidence index

| Artifact | Path |
|---|---|
| Full Ghidra decompilation of `FnHotkeyUtility.exe` | `50-ghidra/fnhotkeyutility/decompile.txt` (5447 lines) |
| Vtables + RTTI (class `CMoniterWmiUtilityEvent`) | `50-ghidra/fnhotkeyutility/vtables.txt`, `.../vtables-decompile.txt` |
| String xrefs | `50-ghidra/fnhotkeyutility/stringrefs.txt` |
| Service + ControlLib RE report | `50-ghidra/lenovoutilityservice/REPORT.md` |
| ACPI event chain / `_WED` table | `20-acpi/analysis/01-event-chain.md` |
| `_WDG` GUID map (generated) | `20-acpi/analysis/04-wmi-guid-map.md` |
| LFCN field layout | `20-acpi/analysis/02-lfcn-layout.md` |
| Windows package stack | `10-extracted/analysis/WINDOWS-STACK.md` |

## 7. Confirmation from the firmware's own MOF (independently decoded)

`20-acpi/mof/DECODED.md` + `mof/DSDT.dsl_WQDA_1043573.mof` - the BMOF blob of device `WMIU` decoded with the
reference `bmfdec` implementation gives:

```mof
[WMI, Dynamic, Provider("WmiProv"), Description("Lenovo Utility Key Press Event"),
 guid("{8fc0de0c-b4e4-43fd-b0f3-8871711c1294}")]
class LENOVO_UTILITY_EVENT : WMIEvent {
  [key, read] string InstanceName;
  [read] boolean Active;
  [WmiDataId(1), read, Description("Lenovo Utility Press key Event")] uint32 PressTypeDataVal;
};
```

So the event property carrying the switch notification is **`PressTypeDataVal` (uint32)**, the class is read-only
(`WMIEvent`, no write path), and its GUID is byte-for-byte the GUID bound by Linux's `ideapad_wmi`. No class in any
firmware blob mentions "camera" - the switch is an opaque code, which is why its meaning had to be recovered from
the Windows binary.

## 8. Residual uncertainty (stated, not hidden)

- ~~The WMI property carrying the event id~~ **RESOLVED, no longer an inference**: the WMI sink
  `CMoniterWmiUtilityEvent::Indicate` = `FUN_140013730` @`0x140013730` calls
  `IWbemClassObject::Get(L"PressTypeDataVal", 0, &VARIANT, NULL, NULL)` (vtable slot 4), reads `VARIANT.lVal`,
  `VariantClear`s, then calls `FUN_140020480(lVal)`. Sink vtable `@0x14003F550` =
  `[QI 0x140013040, AddRef 0x140012FF0, Release 0x1400136F0, Indicate 0x140013730, SetStatus 0x1400137C0]`
  (QI accepts only `IID_IUnknown` / `IID_IWbemObjectSink`). Combined with the firmware MOF (`§7`), the raw id space
  **is** `LENOVO_UTILITY_EVENT.PressTypeDataVal` = `_WED(0xD0)`.
- The raw-id -> handler-id table was verified twice independently: from the decompiled switch bodies, and by decoding
  the 41-entry rel32 jump table directly out of the file image (raw file offset `0x1FCE8`, dispatch
  `jmp image_base+rel`); raw `0x0C -> 0x1E`, raw `0x0D -> 0x1F`, raw `2 -> 0x1A`, raw `3 -> 0x1B`.
- `LSKV = 0x0B/0x0C` for camera ON/OFF is still derived from the two agreeing static tables
  (`_WED` mapping + Windows raw-event dispatch), **not** from a captured physical toggle - no hardware write and no
  physical actuation were performed, per user directive.
- `e_Event_Camera` (id 4) is emitted by `FUN_140008fd0` @`0x140008fd0` from bit 7 of the `\\.\EnergyDrv` notify
  DWORD; the 48 call sites of `g_HandleEvent` were enumerated and only `0x140009021` passes id 4.
- `IAMCameraControl` property index 8 (used for camera privacy) is outside the documented 0..6 range -> vendor/UVC
  extension [INFERENCE]. `Flags = 2` = `CameraControl_Flags_Manual`.
- The EC firmware is closed, so the EC's own semantics for `LSKV` values are not independently observable.
