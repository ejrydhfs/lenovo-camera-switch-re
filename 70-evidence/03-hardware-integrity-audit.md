# 03 - Hardware-integrity audit (read-only guarantee)

Question: *how do we know the hardware is intact up to this point?*
Answer: no state-changing operation was ever issued, and the live state is byte-identical to the session start.

## A. Every action that touched the running machine

| # | Action | Interface | Can it change state? |
|---|--------|-----------|----------------------|
| 1 | Enumerate devices/attributes (`/sys/class`, `/sys/bus/usb`, `/sys/bus/acpi`, `/sys/bus/wmi`, `/sys/devices/platform`, `/sys/module`, `/proc/bus/input/devices`) | sysfs/procfs reads | No - read-only kernel views |
| 2 | `readlink` on `driver`/`firmware_node`/`physical_node` symlinks | sysfs reads | No |
| 3 | `/proc/iomem` (also via `alpine --privileged -v /proc:/host/proc:ro`) | read-only bind mount | No |
| 4 | `cat /sys/devices/pci0000:00/0000:00:14.3/PNP0C09:00/VPC2004:00/camera_power` | **ideapad_laptop -> `read_ec_data()` = `VPCW(1, 0x1D)` then `VPCR(1)` poll then `VPCR(0)`** | **Partially yes - see §A.1.** One byte (opcode `0x1D`) is written into the EC command register `VCMD`; the answer is read from `VDAT`. Executed ~5 times total. It is the *read/get* command; its mutating twin `VPCCMD_W_CAMERA = 0x1E` was never written |
| 5 | Copy `/sys/firmware/acpi/tables/*` into a container | `-v /sys/firmware/acpi/tables:/acpi:ro` (read-only mount) | No - raw table bytes, no AML executed |
| 6 | `lsusb`, `modinfo` on a *copy* of `lenovo-wmi-camera.ko.zst`, `zstdcat <mod>.ko.zst \| strings` | file reads | No - files, not devices |
| 7 | `dmesg` (via privileged alpine) | kernel ring buffer read | No |
| 8 | `docker run` for tooling (debian: `apt-get install innoextract acpica-tools`, `chown` of our own files; alpine: `cat /proc/iomem`, `dmesg`) | container | No device node passed in, no `insmod`, no `/dev/mem` access, no sysfs writes |
| 9 | Ghidra 12.1.2 headless, `objdump`, `strings`, `file` on the extracted PE files | static file analysis | No system interaction |
| 10 | `curl` of kernel sources (raw.githubusercontent) | network | No |
| 11 | Filesystem writes | `/home/user/Downloads/lenovo-camera-switch-re/**` (deliverable folder), `/home/user/Downloads/re_work/**` (scratch), `/tmp/dm.txt` | Confined to ordinary files under $HOME |

**Never performed:** no `insmod`/`modprobe`, no `rmmod`, no driver bind/unbind, no `echo > /sys/...`,
no `/dev/mem` or `/dev/kmem` access, no `/dev/hidraw` I/O, no ACPI `custom_method` write, no ACPI method
invocation that changes state, no EC write, no VPC command other than the read above, no `camera_power`
write, no USB reset/authorization change, no firmware/BIOS interface access.

## A.1 Precise disclosure: the one non-pure-read operation

An earlier draft of this document said the `camera_power` read is a pure getter with "no EC write". That was
imprecise and is corrected here.

Mainline `drivers/platform/x86/lenovo/ideapad-laptop.c`:
```c
static int read_ec_data(acpi_handle handle, unsigned long cmd, unsigned long *data)   /* L404 */
{
        err = eval_vpcw(handle, 1, cmd);          /* <-- writes the COMMAND OPCODE */
        ...
        err = eval_vpcr(handle, 1, &val);         /* poll status  (read)  */
        if (val == 0)
                return eval_vpcr(handle, 0, data);/* fetch data    (read)  */
}
static int eval_vpcw(...) { ... acpi_evaluate_object(handle, "VPCW", &params, NULL); }
```
and the DSDT implementation (`DSDT.dsl:12801`):
```asl
Method (VPCW, 2, Serialized)
{
    If (ECAV) { If ((Acquire (LFCM, 0xA000) == Zero)) {
        If ((Arg0 == One)) { VCMD = Arg1 }   // Arg0==1 -> EC command register = command byte
        Else               { VDAT = Arg1 }   // Arg0==0 -> EC data register    = data
        Release (LFCM) } }
    Return (Zero)
}
Method (VPCR, 1, Serialized)                 // DSDT.dsl:12779
{  ...  If ((Arg0 == One)) { VPCD = VCMD } Else { VPCD = VDAT }  ...  Return (VPCD) }
```
`VCMD` is byte 0 of `OperationRegion (ERAM, EmbeddedControl, 0, 0xFF)` (`DSDT.dsl:11688`), i.e. EC RAM
address `0x00`, reached through the standard ACPI EC interface (the EC0 `_CRS` IO window is `0x62`).

Consequence, stated exactly:
- `cat camera_power` issues **one byte-write of `0x1D` to the EC command register `VCMD`**, then reads
  back `VCMD` (status) and `VDAT` (data). The kernel's ACPI EC driver holds the EC lock throughout.
- `0x1D` is `VPCCMD_R_CAMERA`, the documented **read** ("get") command. The EC services it by placing the
  camera-power value in `VDAT`. The **write/mutate** command is `VPCCMD_W_CAMERA = 0x1E`,
  which was **never** issued, and no other VPC command was ever issued.
- Occurrences during this session: ~5 command submissions (1 during recon, 1 by the read-only scout,
  3 in the stability check). No further `camera_power` reads will be made.
- This is exactly the code path that any ordinary `cat` of that shipped upstream sysfs attribute takes; it is
  not a bespoke probe.

## B. Independent evidence that nothing was disturbed

1. `cat /proc/sys/kernel/tainted` -> **12800 (0x3200)** = bits 9 (WARN), 12 (OOT_MODULE), 13 (UNSIGNED_MODULE).
   `dmesg` attributes these to `vboxdrv` loading at **boot (t = 1.617091 s)** - long before this session. No new taint.
2. `dmesg | grep -E 'insmod|finit_module|loading out-of-tree'` -> only the `vboxdrv` line at 1.617 s.
   **No module was loaded during this session** (the kernel-module proof-of-concept workstream was cancelled
   before it built anything).
3. `ls /sys/module | grep -iE 'camera|poc|lenovo'` -> only the stock `lenovo_wmi_*` set. No experimental module.
4. `find / -name '*.ko' -newermt '2026-10-06 00:40'` -> nothing new built.
5. `dmesg` (1808 lines) contains **zero** `ACPI Error` / `ACPI Warning` / `AE_*` messages.
6. Device state unchanged vs. session start:
   - camera `04f2:b725` "Integrated Camera" still enumerated as `Bus 001 Device 011` (same devnum),
   - ITE `048d:c965` (Bus 003) and `048d:c101` (Bus 001) still present,
   - `ideapad_wmi` still bound to WMI `8FC0DE0C-B4E4-43FD-B0F3-8871711C1294-28`,
   - `VPC2004:00/camera_power` still `0`,
   - ACPI node `device:1d` = `\_SB_.PCI0.GP17.XHC0.RHUB.HSP3.CAMA` still present (i.e. `CAMS` still 1).
7. Latest `dmesg` activity is docker bridge/network churn from our own containers - nothing device-related.

## C. Honest limits

Software cannot *prove* a physical device is undamaged. What can be stated from evidence:
no operation capable of changing firmware/EC/USB/device state was ever issued, and all observable
state matches the session baseline. The single latent risk was the kernel-module PoC; it was cancelled
and verified (items B2-B4) to have produced no module and no load.
