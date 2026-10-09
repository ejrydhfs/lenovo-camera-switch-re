#!/usr/bin/env python3
"""Live indicator for the camera privacy switch: logs camera-on-USB presence and
the ideapad `camera_switch` value, printing only on change.

Tail it while moving the switch:
    tail -f 70-evidence/camera-presence.log
"""
import glob
import time

ATTR = "/sys/devices/pci0000:00/0000:00:14.3/PNP0C09:00/VPC2004:00/camera_switch"
LOG = "/out/camera-presence.log"


def log(msg):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)
    with open(LOG, "a") as fh:
        fh.write(line + "\n")


def camera_present():
    for d in glob.glob("/sys/bus/usb/devices/*/"):
        try:
            with open(d + "idVendor") as fh:
                if fh.read().strip() != "04f2":
                    continue
            with open(d + "idProduct") as fh:
                if fh.read().strip() == "b725":
                    return True
        except OSError:
            continue
    return False


def attr():
    try:
        with open(ATTR) as fh:
            return fh.read().strip()
    except OSError:
        return "n/a"


prev = None
log(f"watching: camera on USB = {'yes' if camera_present() else 'no'}, "
    f"camera_switch = {attr()}  (move the switch now)")

while True:
    cur = (camera_present(), attr())
    if cur != prev:
        cam, sw = cur
        log(f"camera on USB: {'YES' if cam else 'no '}   camera_switch: {sw}"
            f"   -> {'CAMERA ENABLED' if sw == '1' else 'CAMERA DISABLED (privacy)'}")
        prev = cur
    time.sleep(0.5)
