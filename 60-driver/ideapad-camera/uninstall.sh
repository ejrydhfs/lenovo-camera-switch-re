#!/bin/sh
# Revert to the in-tree ideapad-laptop module.
set -e

KVER=$(uname -r)
DEST=/lib/modules/$KVER/updates/ideapad-laptop.ko

[ "$(id -u)" = 0 ] || { echo "error: run as root" >&2; exit 1; }

if lsmod | grep -q '^ideapad_laptop'; then
	modprobe -r ideapad_laptop 2>/dev/null || rmmod ideapad_laptop || true
fi

rm -f "$DEST"
depmod -a "$KVER"
modprobe ideapad_laptop

echo "reverted to: $(modinfo -F filename ideapad_laptop)"
