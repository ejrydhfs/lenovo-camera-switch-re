#!/usr/bin/env python3
"""Monitor the Lenovo camera privacy switch.

Logs, with timestamps:
  * input events of type EV_SW (SW_CAMERA_LENS_COVER) from the
    "Ideapad extra buttons" input device, and
  * changes of the ideapad `camera_switch` sysfs attribute (1 = camera on).

Read-only: opens an event device and reads attributes.
"""
import glob
import os
import select
import struct
import sys
import time

ATTR = "/sys/devices/pci0000:00/0000:00:14.3/PNP0C09:00/VPC2004:00/camera_switch"
LOG = "/out/camera-switch-trace.log"

EV_SYN, EV_KEY, EV_SW = 0x00, 0x01, 0x05
SW_NAMES = {0x09: "SW_CAMERA_LENS_COVER"}
EVENT_FMT = "llHHi"           # 64-bit timeval + type + code + value
EVENT_SIZE = struct.calcsize(EVENT_FMT)


def log(msg):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)
    with open(LOG, "a") as fh:
        fh.write(line + "\n")


def find_event_dev():
    for inp in sorted(glob.glob("/sys/class/input/input*/")):
        try:
            with open(inp + "name") as fh:
                if fh.read().strip() != "Ideapad extra buttons":
                    continue
        except OSError:
            continue
        evs = glob.glob(inp + "event*")
        if evs:
            return "/dev/input/" + os.path.basename(evs[0])
    return None


def read_attr():
    try:
        with open(ATTR) as fh:
            return fh.read().strip()
    except OSError as exc:
        return f"err({exc.errno})"


dev = find_event_dev()
log(f"monitor start: event dev = {dev}, camera_switch = {read_attr()}")
if not dev:
    log("FATAL: 'Ideapad extra buttons' input device not found")
    sys.exit(1)

fd = os.open(dev, os.O_RDONLY | os.O_NONBLOCK)
last_attr = read_attr()
log(f"initial camera_switch = {last_attr} (1 = camera enabled, 0 = privacy switch off)")

while True:
    r, _, _ = select.select([fd], [], [], 1.0)
    if r:
        data = os.read(fd, EVENT_SIZE * 64)
        for off in range(0, len(data) - EVENT_SIZE + 1, EVENT_SIZE):
            sec, usec, etype, code, value = struct.unpack_from(EVENT_FMT, data, off)
            if etype == EV_SW:
                log(f"EV_SW {SW_NAMES.get(code, hex(code))} = {value}"
                    f"  -> {'lens OPEN (camera on)' if value == 0 else 'lens COVERED (camera off)'}")
    cur = read_attr()
    if cur != last_attr:
        log(f"camera_switch changed: {last_attr} -> {cur}")
        last_attr = cur
