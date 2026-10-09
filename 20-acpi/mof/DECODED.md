# MOF / WMI class schema - decoded from the firmware's BMOF blobs

Status: **verified by running a real decoder**. The BMOF blobs were extracted from the ACPI tables and decompressed
with the reference implementation `pali/bmfdec` (`80-tools/bmf2mof`, built from source). Nothing here is inferred.

## Pipeline (all steps re-runnable)

```sh
# 1. extract: parse `Name (WQxx, Buffer (0xNN))` hex out of 20-acpi/dsl/*.dsl  -> 20-acpi/mof/raw/*.bmof
#    (done by the orchestrator; MANIFEST.txt records byte-level self-consistency)
# 2. build decoder
cd 80-tools && make            # bmf2mof, bmfdec, bmfparse
# 3. decode
for f in ../20-acpi/mof/raw/*.bmof; do ./bmf2mof "$f" > ../20-acpi/mof/mof/$(basename $f .bmof).mof; done
```

## Blob format (verified byte-level)

All five blobs are Microsoft **BMOF / Binary-MOF** containers with a **DS-01**-compressed payload:

| Field | Value |
|---|---|
| offset 0 | magic, stored as `46 4F 4D 42` ("FOMB" - i.e. the ASCII for `BMOF` in reversed order) |
| offset 4 | version `01 00 00 00` |
| offset 8 | compressed size (u32 LE) |
| offset 12 | decompressed size (u32 LE) |
| offset 16 | payload, starts `44 53 00 01` = `"DS"`, compression format 1 (Microsoft DS-01/DoubleSpace LZ) |

Extraction check: for every blob `16 + compressed_size == declared buffer length`, and the DS-01 signature is present.

| Blob | ACPI table | device | buffer | compressed | decompressed | MOF output |
|---|---|---|---|---|---|---|
| `WQDA` | DSDT | `WMIU` (`_UID LSK20`) | 1048 | 1032 | 3166 | `mof/DSDT.dsl_WQDA_1043573.mof` |
| `WQBD` | DSDT | `WMI4` | 629 | 613 | 1528 | `mof/DSDT.dsl_WQBD_484982.mof` |
| `WQDD` | DSDT | `GZFD` (`_UID GMZN`) | 19821 | 19805 | 130240 | `mof/DSDT.dsl_WQDD_770853.mof` |
| `WQBA` | SSDT3 | AMD/ASMI | 2647 | 2631 | 14136 | `mof/SSDT3.dsl_WQBA_76874.mof` |
| `WQ00` | SSDT6 | brightness WMI | 893 | 877 | 2920 | `mof/SSDT6.dsl_WQ00_242275.mof` |

## The class that carries the camera switch (decisive)

`mof/DSDT.dsl_WQDA_1043573.mof` - device `WMIU`, i.e. the `LSK20` device that `_QDF` notifies with `0xD0`:

```mof
[WMI, Dynamic, Provider("WmiProv"), Locale("MS\\0x409"),
 Description("Lenovo Utility Key Press Event"), guid("{8fc0de0c-b4e4-43fd-b0f3-8871711c1294}")]
class LENOVO_UTILITY_EVENT : WMIEvent {
  [key, read] string InstanceName;
  [read] boolean Active;
  [WmiDataId(1), read, Description("Lenovo Utility Press key Event")] uint32 PressTypeDataVal;
};

[WMI, Dynamic, Provider("WmiProv"), Locale("MS\\0x409"),
 Description("LENOVO_UTILITY_DATA class"), guid("{ce6c0974-0407-4f50-88ba-4fc3b6559ad8}")]
class LENOVO_UTILITY_DATA {
  [key, read] string InstanceName;
  [read] boolean Active;
  [WmiMethodId(1), Implemented, Description("Utility 3.1 function is Support or the function Version")]
    void GetIfSupportOrVersion([in, Description("Control type")] uint32 datatype,
                               [out, Description("0 is not support 1,2,3...version")] uint32 Data);
};
```

Confirmations this provides:

1. The event GUID in the firmware MOF is **`8fc0de0c-b4e4-43fd-b0f3-8871711c1294`** - exactly the GUID the Linux
   `ideapad_wmi` driver (and the Windows `FnHotkeyUtility.exe`) bind to.
2. The event property is **`PressTypeDataVal` (uint32)** - this is the value `FUN_140020480` switches on
   (`50-ghidra/fnhotkeyutility/decompile.txt:5250`), and `ValueMap`-free: it is the ACPI `_WED(0xD0)` output,
   i.e. the same id space as `_WED`'s `1..0x26` (guard `param_1 - 1U < 0x29`).
3. `LENOVO_UTILITY_DATA` is the class `LenovoUtilityService.exe` uses (`GetIfSupportOrVersion` = the capability probe
   it calls with `datatype` 5 / 19, matching `50-ghidra/lenovoutilityservice/REPORT.md` §2.3).
4. The class is `WMIEvent`-derived and read-only - **the OS cannot write the switch state through this interface.**

## Other classes decoded (full text in the `mof/` files)

| Class | GUID | Notes |
|---|---|---|
| `Lenovo_BatteryInformation : Lenovo_SystemElement` | `C3A03776-51AC-49AA-AD0F-F2F7D62C3F3C` | WMI4 device |
| `LENOVO_INTELLIGENT_OP_LIST`, `LENOVO_GAMEZONE_*` (fan/CPU-OC/GPU-OC/thermal/power/charge/cooling), `LENOVO_OTHER_METHOD`, `LENOVO_CAPABILITY_DATA_*` | GZFD device GUIDs | `mof/DSDT.dsl_WQDD_770853.mof` (33 KB) |
| `WmiBrightnessNotify` | `603e9613-ef25-4338-a3d0-c46177516db7` | SSDT6 WMI device |
| `OIDPackage`, `GetdValuesPackage`, `OutBuffer`, `DimmSpdBuffer`, `GetMinMaxSteppingPackage`, `AMD_ACPI` | AMD SMU/ASMI | SSDT3 (`WQBA`), not Lenovo |

Notably **no class in any blob mentions "camera"** - the camera switch is carried purely as an opaque event code in
`PressTypeDataVal`, which is why the mapping had to be recovered from the binary (see `analysis/05-camera-switch-mechanism.md`).

## Provenance note

An earlier read-only subagent reported these same conclusions but left its claimed output files
(`80-tools/bmof2mof.py`, `20-acpi/mof/DECODED.md`, `raw/*.bmof`) absent - no such files existed. The blobs, the
decoder build and the `.mof` outputs in this directory were (re)generated and verified by the orchestrator; the
subagent's byte-level format analysis was independently confirmed correct.
