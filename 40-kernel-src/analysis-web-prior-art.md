# PART B -- PRIOR ART (content for $W/40-kernel-src/analysis-web-prior-art.md)

## 1. Upstream driver: lenovo-wmi-camera (the only generic Lenovo camera-button driver)
- Source: https://raw.githubusercontent.com/torvalds/linux/master/drivers/platform/x86/lenovo/wmi-camera.c
- Author Ai Chao <aichao@kylinos.cn>, KylinSoft. Merged from LKML: https://lkml.org/lkml/2024/3/20/311 ("[PATCH v10] platform/x86: add lenovo wmi camera button driver"); first posting https://lkml.rescloud.iu.edu/2402.3/06663.html (2024-02-29).
- Key quotes from the driver:
  - `input_set_capability(priv->idev, EV_SW, SW_CAMERA_LENS_COVER);`
  - `obj->buffer.pointer[0] is camera mode: 0 camera close 1 camera open`
  - `#define WMI_LENOVO_CAMERABUTTON_EVENT_GUID "50C76F1F-D8E4-D895-0A3D-62F4EA400013"`
  - `priv->idev->name = "Lenovo WMI Camera Button";`
- History: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/drivers/platform/x86/lenovo/wmi-camera.c (moved into `lenovo/` subdir by commit 651b57dd40871d4d0d61fb291e7f26e2b8bd69b1, Mark Pearson, 2025-06-11).
- LIMITATIONS for 82JU: binds ONLY GUID 50C76F1F; that WMI device is ABSENT on 82JU (`/sys/bus/wmi/devices/` has no 50C76F1F). The input device is created lazily on the *first* notify (`if (!priv->idev) camera_shutter_input_setup(...)`), so there is no initial-state read and no sysfs value. It cannot serve this machine.

## 2. 82JU already has a WMI device, but ideapad-laptop consumes it as "fn keys" only
- Source line (ideapad-laptop.c, L2333): `{ "8FC0DE0C-B4E4-43FD-B0F3-8871711C1294", &ideapad_wmi_context_fn_keys }, /* Legion 5 */`
- `ideapad_wmi_notify()` handles `IDEAPAD_WMI_EVENT_FN_KEYS` only for the fn-lock LED / special buttons (L2271, L2286). No camera decoding.
- Live: `/sys/bus/wmi/devices/8FC0DE0C-B4E4-43FD-B0F3-8871711C1294-28` present; `50C76F1F-...` absent (confirmed).

## 3. camera_power sysfs and VPCCMD_R_CAMERA = 0x1D semantics
- ABI: https://raw.githubusercontent.com/torvalds/linux/master/Documentation/ABI/testing/sysfs-platform-ideapad-laptop -> quote: "Control the power of camera module. 1 means on, 0 means off." (Date Dec 2010, KernelVersion 2.6.37, Ike Panhc).
- Code: `camera_power_show()` -> `read_ec_data(..., VPCCMD_R_CAMERA, &result)`, `camera_power_store()` -> `write_ec_cmd(..., VPCCMD_W_CAMERA, state)`; attribute gated by `CFG_CAP_CAM_BIT`.
- Constants: `VPCCMD_R_CAMERA = 0x1D`, `VPCCMD_W_CAMERA = 0x1E` (enum immediately after `VPCCMD_W_TOUCHPAD`), i.e. VPC EC commands issued via IO 0x62/0x72.
- POLARITY/VALIDITY on 82JU: live `camera_power` reads `0` while the camera is enumerated. So `0` here does not mean "off"; the VPC command simply does not reflect the e-shutter on this generation. It is therefore NOT a usable present-state source.
- Independently corroborated by userspace prior art (below): "camera_power sysfs always reads 0 on affected hardware -- the EC controls the sensor directly."

## 4. linux-privacy-switch -- the closest working prior art for exactly 82JU (userspace)
- URL: https://github.com/prostopasta/linux-privacy-switch (MIT, Python).
- README quotes: "The ITE Embedded Controller fires a key event when the slider moves, but Linux ignores it. The camera is physically cut by the EC..." and "A systemd daemon intercepts the /dev/input/ event, detects the true camera state via V4L2 frame capture, and applies mic mute/unmute + tray icon in sync."
- `config/devices.conf` ships a profile for this exact model: `match_product_name = 82JU`, `input_device_name = Ideapad extra buttons`, `key_code = 240`, `camera_power_path = /sys/bus/platform/drivers/ideapad_acpi/VPC2004:00/camera_power`, `has_hw_camera_kill = true`; status marked "Needs testing".
- Its stated workaround proves the gap: state is inferred by capturing a V4L2 frame and measuring brightness (`<3% nonzero bytes` = covered), because no reliable kernel state exists.

## 5. SW_CAMERA_LENS_COVER -- established ABI + other drivers (prior art for the intended interface)
- HP: `drivers/platform/x86/hp/hp-wmi.c` has `camera_shutter_input_setup()` creating `"HP WMI camera shutter"` and reporting `SW_CAMERA_LENS_COVER` (https://android-kvm.googlesource.com/linux/+/refs/heads/master/drivers/platform/x86/hp/hp-wmi.c).
- Samsung: https://docs.kernel.org/admin-guide/laptops/samsung-galaxybook.html -> "when block_recording is updated, the input device 'Samsung Galaxy Book Lens Cover' will receive a SW_CAMERA_LENS_COVER switch event which reflects the current state."
- Asus has a dedicated `asic-wmi-hotkeys` issue for the same class of shutter (https://github.com/asus-linux-drivers/asus-wmi-hotkeys-driver/issues/2).
- Semantics: `SW_CAMERA_LENS_COVER` is an `EV_SW` bit in `input-event-codes.h`; `1` = lens covered/closed, `0` = open.

## 6. LHK2019 / HKDV
- ACPI `LHK2019` is the target of the Lenovo "Fn and function keys" Windows package (`ACPI\LHK2019`), i.e. the hotkey/OEM service, not a camera driver: https://www.driveridentifier.com/scan/lenovo-fn-and-function-keys-driver/driver-detail/7B5B21D85E60495EA519475D20F6A100/5481940/b0c5babe8cba5403df77ec7e7becfa8d/1483448139/ACPI-LHK2019
- On 82JU `LHK2019:00` exists as an ACPI device with a `physical_node` but no Linux driver binds it; DSDT `Device (HKDV)` is empty (`_STA` only). No upstream or downstream Linux driver for `LHK2019`/`HKDV` was found (searched LKML, kernel.org, GitHub).

## 7. LENOVO_UTILITY_EVENT / LSKEvent / LSKV / LSKD
- No Linux driver consumes `LENOVO_UTILITY_EVENT` or emits `LSKEvent`. Per project ground truth, the Windows binaries use WMI classes `LENOVO_UTILITY_EVENT` / `LENOVO_GAMEZONE_SMART_FAN_MODE_EVENT` on `ROOT\WMI` (`CMoniterWmiUtilityEvent` "Monitor LSKEvent button done") with strings `SwitchCameraStatus`, `CAMERA_BIT7`. This is Windows-only; there is no Linux equivalent.
- ACPI path that DOES exist on 82JU: `Device(WMIU)` `_UID "LSK20"` whose `_WED` handles `0xD0` and maps `LSKD`, with `Name(LSKD,Zero)` / `LSKD = LSKV` and `Notify(WMIU,0xD0)`. The notification reaches the `8FC0DE0C` WMI device, but no Linux code decodes the camera semantics out of it. Only the firmware blob (BMOF) defines the mapping.

## GAP STATEMENT -- solved vs missing
SOLVED upstream:
- A generic Lenovo camera-button WMI driver exists (`lenovo-wmi-camera`) and reports `SW_CAMERA_LENS_COVER` -- but only for GUID `50C76F1F-D8E4-D895-0A3D-62F4EA400013`, which 82JU does not expose.
- `ideapad-laptop` exposes `camera_power` (VPC 0x1D/0x1E) and maps key 7 -> `KEY_CAMERA`; `SW_CAMERA_LENS_COVER` is the established ABI for privacy shutters (HP, Samsung, other Lenovo GUIDs).
- `legion-laptop` (LLL) contains zero camera code.

MISSING (the actual gap this project fills):
1. Nothing binds/decode the `8FC0DE0C` WMI notify (`0xD0` -> `LSKD`) for camera state on 82JU; `ideapad-laptop` treats that GUID as fn-keys only.
2. No initial-state read of the firmware `CAMS` bit (LFCN region, DSDT.dsl:13785) so userspace can enumerate the current position without moving the shutter.
3. No kernel path mapping the 82JU e-shutter to `SW_CAMERA_LENS_COVER`; userspace is forced into V4L2 frame-brightness heuristics (linux-privacy-switch, and it marks 82JU "Needs testing").
4. `LHK2019`/`HKDV` have no Linux driver (and `HKDV` is an empty ACPI stub).

(Note: two .md deliverables were specified, but this investigator has read-only file access. The full contents for both are provided above: Part A in `legion_exposes_camera`, Part B here in `gap_statement`.)