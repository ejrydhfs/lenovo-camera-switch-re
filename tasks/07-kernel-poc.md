# Task 07: Kernel-module proof of concept - read the camera switch state on THIS live machine
Workspace: $W = /home/user/Downloads/lenovo-camera-switch-re. Output dir: $W/60-driver/poc (create it).
Kernel: 7.2.7-arch1-1 (Arch). Build dir: /lib/modules/7.2.7-arch1-1/build  (symlink target /usr/src/linux;
has Kconfig, Makefile, Module.symvers, vmlinux, System.map, but NO .c source files - do not try to build the tree).
gcc/make are on the host. Loading a module needs root -> use docker:
  docker run --rm --privileged -v /lib/modules:/lib/modules -v $W/60-driver/poc:/poc debian:stable-slim \
    bash -c 'apt-get update -qq && apt-get install -y -qq kmod >/dev/null 2>&1; insmod /poc/<mod>.ko && dmesg | tail -40'
(dmesg works there; the kernel ring buffer is global). NOTE: build with the HOST toolchain and `make -C /lib/modules/7.2.7-arch1-1/build M=$PWD modules`.
If module loading is refused (signature/vermagic), report the exact error and fall back to `modprobe --force` evidence.

## Module requirements (camera_state.ko)
A single module that, at init:
 1. Calls ACPI to evaluate candidate objects and LOGS every result (name, ACPI status, type, raw value):
    - `\_SB.PCI0.GP17.XHC0.RHUB.HSP3.CAMA._STA`   (expect 0x0F when camera present/enabled; 0 when gated)
    - `\_SB.PCI0.GP17.XHC0.RHUB.HSP3._UPC`        (package; first element 0xFF = enabled, 0 = disabled)
    - also try `\_SB.PCI0.GP17.XHC0.RHUB.HSP2.*`, `HSP4.*`, and any sibling that exists (find real paths first
      by reading the DSDT - `grep -n "RHUB\|HSP3\|CAMA" $W/20-acpi/dsl/DSDT.dsl`).
      Resolve handles with acpi_get_handle(NULL, path, &h) and report AE_NOT_FOUND vs value.
    - dump the camera USB device presence: match USB idVendor 04f2 idProduct b725 (read it in userspace instead if easier).
 2. Attempts a read of the firmware byte `CAMS` (LFCN region, SystemMemory base 0xCCF7D198, offset 0x19B ->
    0xCCF7D333 - verify the offset yourself from $W/20-acpi/dsl/DSDT.dsl:13786-13850): use ioremap/memremap of the
    covering page and log 0x40 bytes, plus whether the address looks like RAM/valid. Guard with
    request_mem_region / release; if it fails, log the error - do NOT crash the machine.
 3. Registers a platform driver for the existing unbound platform device `LHK2019` (modalias platform:LHK2019)
    exposing a read-only sysfs attribute `camera_state` returning the evaluated state (1/0/err), and also tries to
    register an input device reporting `SW_CAMERA_LENS_COVER` from the same value.
 4. Keeps everything non-destructive: no writes to EC/ACPI/memory. Read-only.
Deliverable: $W/60-driver/poc/ with the source, Makefile, and RESULTS.md containing the exact commands run and
the verbatim output/log lines observed (this is the evidence that the mechanism works).
Also record in RESULTS.md: the value read for the current switch position, and whether it is consistent with the
camera being enumerated on USB (it currently is: 04f2:b725).
Acceptance: module builds, loads, and RESULTS.md contains real observed values (or a precise, evidenced blocker).
