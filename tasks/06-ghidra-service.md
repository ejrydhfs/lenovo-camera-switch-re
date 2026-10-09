# Task 06: Ghidra RE of LenovoUtilityService.exe + ControlLib.dll
Binaries: $W/10-extracted/code$getextractpath$/source/lenovoutilityservice.exe (PE32+ console, 232 KB),
         .../controllib.dll (PE32+ 190 KB), .../intelcontrollib.dll
Tools: /opt/ghidra/support/analyzeHeadless (Ghidra 12.1.2), objdump, strings dumps in $W/70-evidence.
Context: the INF binds ACPI\LHK2019 (empty ACPI device, DSDT.dsl:24668 Device(HKDV)). So the service is
started by device presence. Determine what the service actually reads/writes.
Deliverable: $W/50-ghidra/lenovoutilityservice/REPORT.md + raw decompiler output in same dir, answering:
 1. Does it open \\.\ACPI#... or any device path? Which? With which IOCTLs (list control codes)?
 2. Does it talk to HID (LSK_SetFeature / HidD_SetFeature / hid.dll) and to which device (VID/PID, usage page)?
 3. Does it use WMI (IWbemLocator/ConnectServer/ExecNotificationQueryAsync)? Which namespace/class/query?
 4. Does it read any camera state, and from where? Any registry keys or config files it consults?
 5. The exports/CLSIDs of ControlLib.dll and the LHK2019 relationship.
Acceptance: REPORT.md answers 1-5 with addresses, quoted strings and imported API names; mark [INFERENCE]
where the call graph is not fully resolved. Do NOT guess silently.
