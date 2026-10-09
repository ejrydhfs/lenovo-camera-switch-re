# Linux driver: report the Lenovo camera privacy switch (82JU / Legion 5 15ACH6H)

Status: **implemented, built, loaded and verified on the live machine, then ruled unnecessary** - see "Verification"
and the verdict below. It is kept as the reference for the explicit `SW_CAMERA_LENS_COVER` interface.

## What was changed

`ideapad-laptop.c` in the kernel tree (`drivers/platform/x86/lenovo/ideapad-laptop.c`) already owns the relevant
ACPI-WMI device: GUID `8FC0DE0C-B4E4-43FD-B0F3-8871711C1294` (the "Legion 5" fn-key handler). The driver is
extended rather than replaced - see `0001-ideapad-laptop-report-camera-privacy-switch.patch` (10 hunks, 254 lines).

The RE work (`../README.md`) established two independent firmware sources for the switch position:

1. **Firmware bit `CAMS`** (LFCN+0x19B, phys `0xCCF7D333`), observable through ACPI as `_STA` of the camera port's
   child device `\_SB.PCI0.GP17.XHC0.RHUB.HSP3.CAMA`. This was assumed to be the absolute switch position; the live
   measurement **disproved** that - `HSP3.CAMA._STA` stayed `0x0f` across every toggle
   (`70-evidence/camera-presence.log`). It is a boot/config bit used for ACPI enumeration, not live state.
2. **Transition events** - the EC pushes the new position through the `LENOVO_UTILITY_EVENT` WMI class
   (notify `0xd0`, property `PressTypeDataVal`) with values **`0x0c` = camera on** and **`0x0d` = camera off**.
   This is the real live state source and the path this driver intercepts.

## Interfaces exposed

| Interface | Meaning |
|---|---|
| `/sys/devices/.../VPC2004:00/camera_switch` | the firmware `CAMS` bit (`1` = camera enabled at ACPI enumeration, `0` = disabled). Read-only. **Not the live switch position** - see the verdict. Only present when the ACPI handle resolved. |
| input `SW_CAMERA_LENS_COVER` (bit 0x09) on the existing **"Ideapad extra buttons"** device | standard switch semantics: `1` = lens covered / camera off, `0` = lens open / camera on. Reported on change, and readable any time via `EVIOCGSW`. |

Polarity note: the sysfs value is the *switch position* (1 = on), while `SW_CAMERA_LENS_COVER` is deliberately the
*kernel-standard* inverted convention (1 = covered), so tools like libinput/GNOME behave correctly.

## Design

- `ideapad_camera_switch_setup()` resolves the ACPI handle from `camera_switch_path`
  (module parameter, default `\_SB.PCI0.GP17.XHC0.RHUB.HSP3.CAMA`) and is called **before** `ideapad_input_init()`
  so `input_set_capability(EV_SW, SW_CAMERA_LENS_COVER)` and the sysfs visibility rule can consult it. This ordering
  matches the existing `camera_power` attribute, whose `is_visible` already depends on state set in probe.
- `ideapad_camera_switch_start()` reports the initial state (so `EVIOCGSW` is correct from the first open) and arms
  a 2 s polling work item. Polling is the safety net for missed events and is what makes the state correct without
  the user touching anything.
- `ideapad_wmi_notify()` intercepts event values `0x0c`/`0x0d` and reports them as the switch, **before** the generic
  `ideapad_input_report()`, so they are not emitted as bogus key presses (previously `sparse_keymap_report_event()`
  silently dropped them because the keymap has no entry for these ids).
- `ideapad_camera_switch_stop()` clears the active flag and `cancel_delayed_work_sync()`s on removal; the re-arm is
  guarded by the flag so no work can be queued after teardown.
- **Read-only by construction**: only `acpi_evaluate_integer(_STA)`, `input_report_switch()` and sysfs reads. There is
  no write to the EC, the firmware, VPC or any ACPI method that changes state. (`_STA` reads the firmware's `CAMS`
  bit; the WMI class is a read-only `WMIEvent`.)

## Build

```sh
make -C /lib/modules/$(uname -r)/build M=$PWD modules
```
Requires the kernel build tree (headers, `Module.symvers`, configured `.config`). Verified against
`7.2.7-arch1-1` with gcc 16.2.1 (the exact compiler that built the stock modules); `CONFIG_MODVERSIONS` is off and
`MODULE_SIG_FORCE` is unset, so the module loads (with the unsigned-module taint, as other local modules do).

## Install / test

```sh
cd 60-driver/ideapad-camera        # scripts live next to the module source
sudo ./install.sh                  # build, install to /lib/modules/<ver>/updates/, depmod, swap the live module
cat /sys/devices/pci0000:00/0000:00:14.3/PNP0C09:00/VPC2004:00/camera_switch
sudo ./uninstall.sh                # remove the override and reload the in-tree module
```

`install.sh` replaces the running `ideapad_laptop` module (rmmod + insmod). This is reversible and does not change
any hardware state; `/lib/modules` keeps the in-tree module so a reboot restores stock behaviour unless you install.

## Verification performed

| Check | Result |
|---|---|
| Compiles against 7.2.7-arch1-1 | clean, no warnings |
| Probes | `ideapad_acpi VPC2004:00: camera privacy switch at \_SB.PCI0.GP17.XHC0.RHUB.HSP3.CAMA` (handle resolved) |
| `camera_switch` attribute | exists, reads **1** |
| Cross-check of that value | ACPI node `HSP3.CAMA` present ⇒ firmware `CAMS == 1` ⇒ agrees with `1`, but see the verdict: this is not the live switch state |
| Input capability | `Ideapad extra buttons` capabilities: `sw=200` (bit 9 = `SW_CAMERA_LENS_COVER`), `ev=33` (SYN/KEY/SW) |
| Regressions | no new dmesg errors/warnings; camera still enumerated; `camera_power` still `0`; rfkill/backlight unaffected |

### End-to-end verification (physical toggle, 2026-10-06)

The switch was moved repeatedly with `monitor-camera-switch.py` running:

```sh
60-driver/monitor-camera-switch.py     # log: 70-evidence/camera-switch-trace.log
```

Result (`70-evidence/camera-switch-trace.log`, `70-evidence/camera-presence.log`):

- **12 `EV_SW SW_CAMERA_LENS_COVER` transitions** tracking the switch exactly - the WMI event path works, and the
  `0x0c`/`0x0d` interception in `ideapad_wmi_notify()` is correct.
- the camera dropped off USB `1-3` and returned on every toggle.
- sysfs `camera_switch` stayed `1` throughout, confirming it reports `CAMS` and not the switch.

### Verdict: the driver is not needed

The measurement above shows userspace already has the state without any new kernel code:

- the camera appearing and disappearing on USB *is* the switch position, and
- the WMI event is available to any consumer once `ideapad-laptop`'s keymap knows the two ids.

A driver would just re-publish state the system already exposes. It is kept here as the reference implementation
for the explicit `SW_CAMERA_LENS_COVER` interface, and as the source of the two keymap entries worth upstreaming.

If upstreaming anyway, drop the `CAMS`-based sysfs attribute - the measurement disproved it as a state source.

## Upstreaming notes

- The patch is deliberately minimal and self-contained; it would go to `platform-driver-x86@vger.kernel.org`
  with the DSDT evidence in `../20-acpi/analysis/05-camera-switch-mechanism.md`.
- A cleaner long-term shape would auto-discover the camera port node (walk `\_SB.PCI0.GP1x.XHC0.RHUB.*` for a child
  named `CAMA`) instead of the module parameter, and use the WMI event as the only wake-up source.
- `SW_CAMERA_LENS_COVER` is already the interface used by `drivers/platform/x86/lenovo/wmi-camera.c` for the
  (different GUID) camera-button devices, so the userspace contract is consistent.
