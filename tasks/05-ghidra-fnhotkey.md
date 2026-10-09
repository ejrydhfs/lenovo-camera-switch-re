# Task 05: Ghidra RE of FnHotkeyUtility.exe (camera switch logic)
Binary: $W/10-extracted/code$getextractpath$/source/fnhotkeyutility.exe (PE32+ x86-64, 785 KB)
Tools: /opt/ghidra/support/analyzeHeadless (Ghidra 12.1.2, JDK 27), objdump, strings dumps in $W/70-evidence.
Ghidra usage: `analyzeHeadless <projdir> <projname> -import <bin> -scriptPath <dir> -postScript <script.py>`
(or use `-postScript` with a Java/Python script printing decompilation of named functions).
Known symbols/strings to target (see $W/70-evidence/strings16-fnhotkeyutility.exe.txt):
  CMoniterWmiUtilityEvent::_Thread_WmiUtilityEventMonitor, StartUtilityEventMonitor
  CMoniterWmiGetFnQ::_Thread_WmiFnQMonitor
  MsgLogic::g_HandleEvent, "Init CAMERA_BIT7", "SwitchCameraStatus in ....", "camera unkown status!"
  e_Event_CAMERA_BG_BLUR, e_Event_FnQ, e_Event_FnQ_X60, "CameraPrivacy SwitchCameraStatus", pCameraControl, pMoniker
  "SELECT * FROM LENOVO_UTILITY_EVENT", "SELECT * FROM LENOVO_GAMEZONE_SMART_FAN_MODE_EVENT"
Deliverable: $W/50-ghidra/fnhotkeyutility/REPORT.md plus raw decompiler output in the same dir, containing:
 1. Which WMI class/namespace/product the event comes from, and the exact event-data decoding:
    every event id / bit test / mask (especially CAMERA_BIT7: which byte and bit, and 0/1 meaning).
 2. The mapping of WMI event data -> internal MsgLogic event enum (e_Event_*), and what each does
    regarding the camera (SwitchCameraStatus: what it sets, what it calls).
 3. Whether the camera switch STATE is obtained by querying something else (COM object, WMI query,
    SetupAPI device enumeration, registry) rather than from the event, and if so, exactly what.
 4. Pseudocode or annotated decompilation for the relevant functions (paste into REPORT.md).
Acceptance: REPORT.md answers 1-4 with function names+addresses and quoted constants. State explicitly
what is certain vs [INFERENCE].
