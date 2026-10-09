#!/bin/sh
# Install the patched ideapad-laptop module (camera privacy switch reporting).
# Writes only to /lib/modules/<uname -r>/updates/ and swaps the live module.
set -e

KVER=$(uname -r)
KDIR=/lib/modules/$KVER/build
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=ideapad-laptop.ko
DEST=/lib/modules/$KVER/updates

[ "$(id -u)" = 0 ] || { echo "error: run as root" >&2; exit 1; }
[ -d "$KDIR" ] || { echo "error: kernel build tree $KDIR missing" >&2; exit 1; }

echo "== building for $KVER"
make -C "$KDIR" M="$HERE" modules

echo "== installing $MOD -> $DEST"
mkdir -p "$DEST"
cp "$HERE/$MOD" "$DEST/$MOD"
depmod -a "$KVER"

echo "== swapping the live module"
if lsmod | grep -q '^ideapad_laptop'; then
	modprobe -r ideapad_laptop 2>/dev/null || rmmod ideapad_laptop
fi
modprobe ideapad_laptop

echo "== verifying"
ATTR=/sys/devices/pci0000:00/0000:00:14.3/PNP0C09:00/VPC2004:00/camera_switch
if [ -r "$ATTR" ]; then
	echo "camera_switch = $(cat "$ATTR")   (1 = camera enabled, 0 = privacy switch off)"
else
	echo "warning: $ATTR not present - check dmesg" >&2
fi
modinfo -F filename ideapad_laptop
echo "done. use ./uninstall.sh to revert."
