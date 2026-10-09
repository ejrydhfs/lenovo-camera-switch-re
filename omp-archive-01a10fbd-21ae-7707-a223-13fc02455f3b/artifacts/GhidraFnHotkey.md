{
  "report": "/home/user/Downloads/lenovo-camera-switch-re/50-ghidra/fnhotkeyutility/REPORT.md (585 lines)",
  "raw_artifacts": [
    "decompile.txt (5447 lines, all string-referencing functions)",
    "decompile-sinks.txt (IWbemObjectSink impls: QueryInterface/AddRef/Release/Indicate/SetStatus for both monitors)",
    "decompile-helpers.txt (OSD FUN_1400184a0, EM IOCTL wrapper FUN_140008a80)",
    "vtables.txt + vtables-decompile.txt (RTTI vtables; *_meta_ptr blocks are dumped one slot early - use the ::vftable blocks)",
    "symbols.txt (655 functions), stringrefs.txt, named-functions.txt, disasm-named.txt",
    "../scripts/{DumpFnHotkey,DumpVtables,DecompileAddrs}.java (reproducible)"
  ],
  "verdicts_on_your_6_points": {
    "1_agree": "AGREE. FUN_140020480 @0x140020480 is the raw-id dispatcher (trace string at 0x1400472C0, guard (u32)(wParam-1) < 0x29, switch jump table decoded raw from file offset 0x1FCE8, bodies 0x1400204BD..0x1400208C7, 'wParam invalid' path 0x1400208D4 -> 0x140047350). Calls MsgLogic::g_HandleEvent = FUN_14001AA60 @0x14001AA60 (8976 bytes, switch at 0x14001b303 `cmp ebx,0x3A`, ids 0..0x3A valid).",
    "2_complete_table": "EXTRACTED, all 59 ids 0..0x3A contiguous (FUN_14001CE70 = map builder, decompile.txt:3986-4706). 4=Camera, 0x1A=FNLK_ON, 0x1B=FNLK_OFF, 0x1C=SERVICE, 0x1D=VOICE, 0x1E=CAMERA_SWITCH_ON, 0x1F=CAMERA_SWITCH_OFF, 0x20=PANEL_RFESHRATE, 0x21=LAUNCH_VANTAAGE, 0x22=DOLBY_THREE_MODE - all confirmed. Full table in REPORT.md section 2.1. Note: 0x21 has NO handler case and NO producer in this binary (dead entry); the switch does not implement 5,6,7,0xC,0xD,0xE,0x11,0x14,0x21.",
    "3_AGREE": "AGREE, and I cross-verified it a second way: decoded the 41-entry rel32 jump table straight out of the file (raw 0x1FCE8, dispatch `jmp image_base+rel`) and read each body's stored constant: raw 0x0C -> 0x1E, raw 0x0D -> 0x1F, raw 2 -> 0x1A, raw 3 -> 0x1B. Evidence for 'raw id == ACPI _WED value' is structural: the sink passes exactly one 32-bit WMI property (PressTypeDataVal) straight into this switch, so the raw id space is the firmware's event id space, 1..0x29.",
    "4_AGREE": "AGREE (decompile.txt:3422-3440). case 0x1E -> OSD asset 0x7E1 + text L\"1\" (VA 0x140039F58) + label L\"CameraHW\"; case 0x1F -> 0x7E2 + L\"0\" (0x140039F98) + L\"CameraHW\". Also verified case 4 uses the same pair (state==0 -> 0x7E2, else 0x7E1). FUN_1400184A0 is the OSD routine (logs 'g_CreateOpenAnimateThread Show OSD %d').",
    "5_AGREE_with_correction": "AGREE on the capability: IOCTL 0x831020DC on \\\\.\\EnergyDrv, DAT_1400560FC = out[0]>>0x18, bit7 = CAMERA_BIT7 -> DAT_140056148 (1 = supported), bit6/bit5/bit3 -> touchpad/mic/numlk; failure default 0xF8. CORRECTION on wording: that byte is a CAPABILITY, not the state. The STATE comes from CameraPrivacy::SwitchCameraStatus = FUN_140007A90 @0x140007a90 (DirectShow: CLSID_SystemDeviceEnum -> CLSID_VideoInputDeviceCategory -> IMoniker::BindToObject(IBaseFilter) -> QI IID_IAMCameraControl -> Get(property=8,&val,&flags) on every camera; state=1 iff all cameras nonzero; then Set(property=8, !state, Flags=2)). IOCTL 0x831020C4 (in dword 7, out dword Data[0], 1 -> OSD 0x7E1 else 0x7E2) is only a FALLBACK used when SwitchCameraStatus returns 0 AND DAT_140056160 bit3 set.",
    "6_RESOLVED_not_inference": "The field is CERTAIN: CMoniterWmiUtilityEvent::Indicate = FUN_140013730 @0x140013730 calls IWbemClassObject::Get(L\"PressTypeDataVal\" @0x14003EE10, 0, &VARIANT, NULL, NULL) via vtable +0x20 (slot 4 = Get; slot 3 is GetQualifierSet - verified against wbemcli.h), reads VARIANT.lVal (stack +0x38 = VARIANT+8), VariantClear, then calls FUN_140020480(lVal). Sink vtable CMoniterWmiUtilityEvent::vftable @0x14003F550 = [0x140013040 QI, 0x140012FF0 AddRef, 0x1400136F0 Release, 0x140013730 Indicate, 0x1400137C0 SetStatus]; QI accepts only IID_IUnknown (0x14002BCF0) or IID_IWbemObjectSink (0x14002BDE8)."
  },
  "key_new_findings": [
    "e_Event_Camera (id 4) is produced ONLY by EM-driver notify bit 7 (0x80) of the \\\\.\\EnergyDrv notify DWORD - FUN_140008FD0 @0x140008fd0 (all 48 call sites of g_HandleEvent enumerated; only 0x140009021 passes 4).",
    "e_Event_CAMERA_SWITCH_ON/OFF (0x1E/0x1F) are produced ONLY by LENOVO_UTILITY_EVENT PressTypeDataVal = 12/13 -> those are pure OSD notifications, no hardware write. This is the firmware-reported switch position Linux can consume.",
    "State semantics: 'state = 1 iff no camera reports 0 via IAMCameraControl::Get(prop 8)'; SwitchCameraStatus then WRITES THE INVERSE (toggle). The OSD displays the PRE-toggle value (observed; intent [INFERENCE]).",
    "IAMCameraControl vtable order verified from strmif.h: GetRange=+0x18, Set=+0x20, Get=+0x28 (so +0x20=Set, +0x28=Get). Property index 8 is outside documented CameraControlProperty 0..6 => vendor/UVC privacy control [INFERENCE]. Flags constant 2 = CameraControl_Flags_Manual.",
    "GUID block at file 0x2F008..0x2F058: CLSID_SystemDeviceEnum, CLSID_VideoInputDeviceCategory, IID_ICreateDevEnum, IID_IBaseFilter, IID_IAMCameraControl.",
    "SetupAPI IS called but only for HID: GUID {4D1E55B2-F16F-11CF-88CB-001111000030} = GUID_DEVINTERFACE_HID at 0x14003AF50, call sites all inside FUN_14000BCE0. NOT used for the camera.",
    "No registry value, no WMI Win32_* query and no SetupAPI path provides camera state - all strings+xrefs enumerated.",
    "FnQ monitor CMoniterWmiGetFnQ (FUN_140013280 thread, FUN_140013090 Indicate) subscribes to ROOT\\WMI class LENOVO_GAMEZONE_SMART_FAN_MODE_EVENT and reads properties Mode/version -> ids 0x0F (FnQ) or 0x10 (FnQ_X60) when version>=4. It never touches the camera."
  ],
  "notes_for_linux_side": [
    "CAMERA_BIT7 is NOT in the WMI payload - the Linux analogue of the capability signal is simply the presence of the LSK20 (PNP0C14, _UID \"LSK20\") WMI device, not a GPIO bit.",
    "The LSKD->PressTypeDataVal mapping is not in this binary (BmofDecode workstream); expect TWO distinct values for camera-on (12) and camera-off (13), i.e. an event, not a level.",
    "No hardware write was performed during this task (static analysis only); machine drivers untouched."
  ]
}