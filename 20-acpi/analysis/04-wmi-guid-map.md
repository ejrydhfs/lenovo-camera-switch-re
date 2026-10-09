# 04 - exact `_WDG` decode (every ACPI WMI device) + live Linux binding

Generated programmatically from `20-acpi/dsl/*.dsl` (`Name (_WDG, Buffer(...))`) on the live machine.

Entry = **20 bytes** (ACPI 6.4): GUID(16) + ObjectId(u16 LE) + InstanceCount(u8) + Flags(u8).
GUID byte order: first three fields little-endian, fourth field raw, last six bytes raw.
ObjectId is used by firmware as the ACPI notify id - `Notify(<device>, <ObjectId>)` - and is exactly what Linux
exposes at `/sys/bus/wmi/devices/<guid>-<n>/notify_id`. Binding column is live from `/sys/bus/wmi/devices/*/driver`.


## `WMI4` (_UID ``) - DSDT.dsl, buffer 0x28 = 40 bytes = 2 entries

| # | GUID | ObjectId (notify id) | Inst | Flags | Bound Linux driver (live) |
|---|------|----------------------|------|-------|---------------------------|
| 1 | `C3A03776-51AC-49AA-AD0F-F2F7D62C3F3C` | 0x4441 | 3 | 0x05 | (unbound) |
| 2 | `05901221-D566-11D1-B2F0-00A0C9062910` | 0x4442 | 1 | 0x00 | wmi-bmof |

## `GZFD` (_UID `GMZN`) - DSDT.dsl, buffer 0x01CC = 460 bytes = 23 entries

| # | GUID | ObjectId (notify id) | Inst | Flags | Bound Linux driver (live) |
|---|------|----------------------|------|-------|---------------------------|
| 1 | `887B54E3-DDDC-4B2C-8B88-68A26A8835D0` | 0x4141 | 1 | 0x02 | lenovo_wmi_gamezone |
| 2 | `92549549-4BDE-4F06-AC04-CE8BF898DBAA` | 0x3242 | 1 | 0x02 | (unbound) |
| 3 | `14AFD777-106F-4C9B-B334-D388DC7809BE` | 0x3342 | 1 | 0x02 | (unbound) |
| 4 | `DA7547F1-824D-405F-BE79-D9903E29CED7` | 0x3442 | 1 | 0x02 | (unbound) |
| 5 | `DC2A8805-3A8C-41BA-A6F7-092E0089CD3B` | 0x3542 | 1 | 0x02 | lenovo_wmi_other |
| 6 | `8C5B9127-ECD4-4657-980F-851019F99CA5` | 0x4142 | 1 | 0x02 | (unbound) |
| 7 | `87FB2A6D-D802-48E7-9208-4576C5F5C8D8` | 0x3341 | 2 | 0x01 | (unbound) |
| 8 | `4DD5BD84-15A9-47E2-AD65-CC61A5C62FD0` | 0x3441 | 6 | 0x01 | (unbound) |
| 9 | `B7F3CA0A-ACDC-42D2-9217-77C6C628FBD2` | 0x3041 | 1 | 0x01 | (unbound) |
| 10 | `887B54E2-DDDC-4B2C-8B88-68A26A8835D0` | 0x3141 | 2 | 0x01 | (unbound) |
| 11 | `93A57CD3-BBC6-46AB-951D-31F17CC968A0` | 0x3241 | 18 | 0x01 | (unbound) |
| 12 | `BFD42481-AEE3-4501-A107-AFB68425C5F8` | 0x00D0 | 1 | 0x08 | (unbound) |
| 13 | `BFD42481-AEE3-4502-A107-AFB68425C5F8` | 0x00E0 | 1 | 0x08 | (unbound) |
| 14 | `D062906B-12D4-4510-999D-4831EE80E985` | 0x00D1 | 1 | 0x08 | (unbound) |
| 15 | `BC72A435-E8C1-4275-B3E2-D8B8074ABA59` | 0x00E1 | 1 | 0x08 | (unbound) |
| 16 | `10AFC6D9-EA8B-4590-A2E7-1CD3C84BB4B1` | 0x00E2 | 1 | 0x08 | (unbound) |
| 17 | `D320289E-8FEA-41E0-86F9-611D83151B5F` | 0x00E3 | 1 | 0x08 | (unbound) |
| 18 | `1E3391A1-2C89-464D-95D9-3028B72E7A33` | 0x00E8 | 1 | 0x08 | (unbound) |
| 19 | `D320289E-8FEA-41E1-86F9-611D83151B5F` | 0x00E4 | 1 | 0x08 | (unbound) |
| 20 | `D320289E-8FEA-41E0-86F9-711D83151B5F` | 0x00E5 | 1 | 0x08 | (unbound) |
| 21 | `D320289E-8FEA-41E0-86F9-811D83151B5F` | 0x00E6 | 1 | 0x08 | (unbound) |
| 22 | `D320289E-8FEA-41E0-86F9-911D83151B5F` | 0x00E7 | 1 | 0x08 | lenovo_wmi_events |
| 23 | `05901221-D566-11D1-B2F0-00A0C9062910` | 0x4444 | 1 | 0x00 | wmi-bmof |

## `WMIU` (_UID `LSK20`) - DSDT.dsl, buffer 0x3C = 60 bytes = 3 entries

| # | GUID | ObjectId (notify id) | Inst | Flags | Bound Linux driver (live) |
|---|------|----------------------|------|-------|---------------------------|
| 1 | `CE6C0974-0407-4F50-88BA-4FC3B6559AD8` | 0x4B53 | 1 | 0x02 | lenovo_wmi_hotkey_utilities |
| 2 | `8FC0DE0C-B4E4-43FD-B0F3-8871711C1294` | 0x00D0 | 1 | 0x08 | ideapad_wmi |
| 3 | `05901221-D566-11D1-B2F0-00A0C9062910` | 0x4144 | 1 | 0x00 | wmi-bmof |

## `?` (_UID `AOD`) - SSDT3.dsl, buffer 0x28 = 40 bytes = 2 entries

| # | GUID | ObjectId (notify id) | Inst | Flags | Bound Linux driver (live) |
|---|------|----------------------|------|-------|---------------------------|
| 1 | `ABBC0F6A-8EA1-11D1-00A0-C90629100000` | 0x4141 | 1 | 0x02 | (unbound) |
| 2 | `05901221-D566-11D1-B2F0-00A0C9062910` | 0x4142 | 1 | 0x00 | wmi-bmof |

## `AWMI` (_UID `0x00`) - SSDT6.dsl, buffer 0x28 = 40 bytes = 2 entries

| # | GUID | ObjectId (notify id) | Inst | Flags | Bound Linux driver (live) |
|---|------|----------------------|------|-------|---------------------------|
| 1 | `603E9613-EF25-4338-A3D0-C46177516DB7` | 0x4141 | 1 | 0x02 | nvidia-wmi-ec-backlight |
| 2 | `05901221-D566-11D1-B2F0-00A0C9062910` | 0x3030 | 1 | 0x00 | wmi-bmof |
