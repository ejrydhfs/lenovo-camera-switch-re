# PART A -- LEGION-LAPTOP DRIVER AUDIT (content for $W/40-kernel-src/analysis-legion-laptop.md)

> Read-only audit. No hardware writes performed (per parent directive). The zstd stream could not be executed/decompressed by this read-only subagent (no shell tool); the equivalent `strings`/binary check was done with a binary regex over the uncompressed .ko plus full source scan.

## 1. Module identity
- Compressed module: `/lib/modules/7.2.7-arch1-1/updates/dkms/legion-laptop.ko.zst` (zstd; uncompressed member `legion-laptop.ko`, 280.1 KiB).
- Uncompressed: `/usr/src/LenovoLegionLinux-1.0.0/legion-laptop.ko`; source `/usr/src/LenovoLegionLinux-1.0.0/legion-laptop.c` (6424 lines).
- DKMS: `/usr/src/LenovoLegionLinux-1.0.0/dkms.conf` -> `PACKAGE_NAME="LenovoLegionLinux"`, `BUILT_MODULE_NAME[0]="legion-laptop"`.
- From `legion-laptop.mod.c`:
  - `MODULE_INFO(depends, "wmi,platform_profile")`
  - `MODULE_INFO(srcversion, "87436180C63740F1CF404E9")`
  - aliases: `acpi*:PNP0C09:*`; WMI `887B54E3-DDDC-4B2C-8B88-68A26A8835D0`, `D320289E-8FEA-41E0-86F9-611D83151B5F`, `bc72a435-e8c1-4275-b3e2-d8b8074aba59`, `10afc6d9-ea8b-4590-a2e7-1cd3c84bb4b1`, `bfd42481-aee3-4502-a107-afb68425c5f8`, `d062906b-12d4-4510-999d-4831ee80e985`, `bfd42481-aee3-4501-a107-afb68425c5f8`, and **`8FC0DE0C-B4E4-43FD-B0F3-8871711C1294`** (the Legion 5 fn-keys GUID).
- Live module params: `/sys/module/legion_laptop/parameters/{force,ec_readonly,enable_platformprofile}`.
- **Loaded but NOT bound**: `/sys/bus/platform/drivers/legion/` contains only `bind`, `module`, `unbind`, `uevent` -- no bound device; `/sys/devices/platform/legion*` matches nothing. So no legion sysfs attributes are live on this machine (DMI/BIOS gate; `force=1` would be needed, not done).

## 2. Camera/shutter/lens/CAM/LHK/HKDV scan -- ZERO matches
- `grep -iE 'camera|shutter|lens|SW_CAMERA|LHK|HKDV|CAMS|input_report_switch|switchdev' legion-laptop.c` -> **0 matches**.
- Same pattern over the *binary* `legion-laptop.ko` -> **0 matches**.
- Whole `/usr/src/LenovoLegionLinux-1.0.0` tree -> only hits are in `6_10_patch/Kconfig` / `Makefile`, which are the kernel patch bundle for the *upstream* `LENOVO_WMI_CAMERA` driver (line 1057/71), i.e. not LLL code.
- No `SW_*`, no switch-capable input device, no EC/WMI decode of `CAMS`/`LSKD` anywhere in the driver.

## 3. EVERY userspace-facing sysfs attribute it creates (when bound)
Attribute group on the platform device (`legion_attribute_group`, source L4713-4750), 32 attrs:
`powermode, lockfancontroller, rapidcharge, winkey, touchpad, gsync, powerchargemode, overdrive, cpumaxfrequency, isacfitforoc, cpu_oc, cpu_shortterm_powerlimit, cpu_longterm_powerlimit, cpu_apu_sppt_powerlimit, cpu_default_powerlimit, cpu_peak_powerlimit, cpu_cross_loading_powerlimit, gpu_oc, gpu_ppab_powerlimit, gpu_ctgp_powerlimit, gpu_ctgp2_powerlimit, gpu_default_ppab_ctrgp_powerlimit, gpu_temperature_limit, gpu_boost_clock, fan_fullspeed, fan_maxspeed, thermalmode, issupportcpuoc, issupportgpuoc, aslcodeversion, igpumode` (+ sentinel).

hwmon device `"legion_hwmon"` via `hwmon_device_register_with_groups(...)` (L5894):
- `temp{1,2,3}_input`, `temp{1,2,3}_label`, `fan{1,2}_input`, `fan{1,2}_label`, `fan{1,2}_target` (sensor_hwmon_attributes L5208), and
- `fan{1,2}_max`, `pwm{1,2,3}_auto_point{1..10}_{pwm,temp,temp_hyst,accel,decel}` (fancurve attrs L5419+).

Other surfaces:
- platform_profile `"lenovo-legion"` (`platform_profile_register`, only if `enable_platformprofile`).
- debugfs `/sys/kernel/debug/legion/{fancurve,ecmemory,ecmemoryram}` (L4008-4014).
- module params: `force`, `ec_readonly`, `enable_platformprofile`.
- (When unbound: none of the above exist; only the `/sys/module/legion_laptop/*` module dir.)

## 4. VERDICT
**NO -- the legion-laptop DKMS driver does NOT expose the camera privacy-switch state in any form.** There is no camera sysfs attribute, no input device, no `SW_CAMERA_LENS_COVER`, no EC read of `CAMS`, and no decode of the `0xD0`/`LSKD` WMI event (its WMI notify handler merely logs and calls `platform_profile_notify`). The only camera-related userspace surface on this machine remains `ideapad-laptop`'s `camera_power` (VPC EC `VPCCMD_R_CAMERA=0x1D` / `VPCCMD_W_CAMERA=0x1E`), which reads `0` live while the Chicony 04f2:b725 camera is enumerated, and emits no input/switch events.

## 5. Live corroboration (read-only)
- `cat /sys/devices/pci0000:00/0000:00:14.3/PNP0C09:00/VPC2004:00/camera_power` -> `0`.
- `/sys/bus/acpi/devices/LHK2019:00/` exists (`status`, `physical_node`, `modalias`) but no driver binds it.
- `/sys/bus/wmi/devices/` lists `8FC0DE0C-B4E4-43FD-B0F3-8871711C1294-28`; **`50C76F1F-D8E4-D895-0A3D-62F4EA400013` is ABSENT** (so lenovo-wmi-camera has nothing to bind).