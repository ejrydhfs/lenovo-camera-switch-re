{
  "status": "complete",
  "assignment": "09-dotnet-verify",
  "deliverables": [
    {
      "path": "10-extracted/analysis/blurswitchcs.decompiled.cs",
      "bytes": 15354,
      "lines": 366,
      "tool": "ilspycmd 11.1.0.9782 (ICSharpCode.Decompiler 11.1.0.9782), installed via `dotnet tool install -g ilspycmd` on dotnet 10.0.112; contains 6 command blocks, unedited stdout",
      "contents": "exact command header + (1) `ilspycmd -t BlurSwitchCS \"$DLL\"` failure, (2) `-l c` type list, (3) full-assembly C# decompile, (4) `-t BlurSwitchCS.ToggleBlurSwitch -il` IL, (5) `--dump-table AssemblyRef`, (6) `--dump-table Assembly`"
    },
    {
      "path": "10-extracted/analysis/WINDOWS-STACK.md",
      "bytes": 26255,
      "lines": 459,
      "contents": "verified architecture, per-file role table, signature/catalogue facts, Q4 answer, verbatim evidence appendix A-D"
    }
  ],
  "key_findings": {
    "dotnet_assembly_corrections": "The task's suggested `ilspycmd -t BlurSwitchCS` FAILS: `BlurSwitchCS` is the NAMESPACE, not a type. The real class is `BlurSwitchCS.ToggleBlurSwitch` (only class in the assembly besides <Module>) with a single method `Switch()`. So the prior scout's 'class BlurSwitchCS, methods ToggleBlurSwitch/SendMessageAsync/OpenAsync' is REFUTED — SendMessageAsync/OpenAsync are WinRT API calls inside Switch(), not class methods.",
    "assembly_identity": "BlurSwitchCS, version 1.0.0.0, TargetFramework .NETFramework v4.6.1, GUID a8bf1931-bcd8-4ccb-b8b6-b75b2f620041, PE32 i386, sha256 4d6a09997bc5ae9b2bff05d40afd281645b6cd60e07647a7b03074c596c0b11f",
    "status_constants_values": "STATUS_SET_BLUR_OFF_OK=10000, STATUS_SET_BLUR_ON_OK=10001, STATUS_SET_FEATURE_ERR=10002, STATUS_RETURN_ERR=10003, STATUS_EXCEPTION=10005, STATUS_SET_TIMEOUT=10006, STATUS_CONNECT_SVR_ERR=10007, STATUS_SVR_REPOND_ERR=10008 (misspelling REPOND is in the binary)",
    "appservice": "AppService name `Lenovo.CameraControlBackgroundService` in package family `E0469640.SmartAppearance_5grkq8ppsgwt4` (NOT E0469640.LenovoUtility_5grkq8ppsgwt4); message ValueSet{Key=ToggleBlurSwitch}, reply Result in {BlurOff,BlurOn,BlurError}, 5000ms timeouts",
    "string_binary_mapping": {
      "fnhotkeyutility.exe": [
        "E0469640.LenovoUtility_5grkq8ppsgwt4",
        "E0469640.LenovoUtility_5grkq8ppsgwt4!LenovoUtility",
        "E046963F.LenovoCompanion_k1h2ywk1493x8",
        "E0469640.SmartAppearance_5grkq8ppsgwt4"
      ],
      "blurswitchcs.dll": [
        "Lenovo.CameraControlBackgroundService",
        "E0469640.SmartAppearance_5grkq8ppsgwt4"
      ]
    },
    "signature": "lenovofnandfunctionkeys.cat = DER PKCS#7 SignedData signed by CN=Microsoft Windows Hardware Compatibility Publisher (issuer Microsoft Windows Third Party Component CA 2012 -> Microsoft Root Certificate Authority 2010). No .sys anywhere in the package. INF: ServiceBinary=%13%\\LenovoUtilityService.exe, SERVICE_AUTO_START(0x2)/SERVICE_OWN_PROCESS(0x10), service LenovoFnAndFunctionKeys.",
    "q4_answer": "NO component independently reads/queries the camera-switch hardware state. The switch state is only READ out of the firmware WMI event payload: fnhotkeyutility.exe subscribes to ROOT\\WMI class LENOVO_UTILITY_EVENT (`SELECT * FROM LENOVO_UTILITY_EVENT`) and masks pInfoData->Data[0] with &8 -> e_Event_CAMERA_SWITCH_ON/OFF. It is write-only toward the camera: (a) `CameraPrivacy SwitchCameraStatus` enumerates video capture monikers and calls pCameraControl[i]->Set (DirectShow IAMCameraControl::Set = Windows camera privacy) and (b) e_Event_CAMERA_BG_BLUR -> BlurSwitchCLR -> BlurSwitchCS.ToggleBlurSwitch.Switch() -> UWP AppService (software blur). Hardware lens/port gating is firmware CAMS, outside the package. \\\\.\\EnergyDrv (external, unshipped) is used for keyboard backlight/GPIO, not camera."
  },
  "verification_notes": "All findings from real tool runs (ilspycmd, file, sha256sum, openssl, grep, iconv). Raw output embedded. [INFERENCE]-tagged items: exact Data[0] bit/mask naming (string says &8 vs constant CAMERA_BIT7), and system.runtime.windowsruntime.dll being an unlisted stray (present in payload dir, absent from INF SourceDisksFiles).",
  "checks_main_agent_should_run": "Read the two deliverables; optionally re-run `~/.dotnet/tools/ilspycmd -t BlurSwitchCS.ToggleBlurSwitch \"$W/10-extracted/code$getextractpath$/source/blurswitchcs.dll\"` and `openssl pkcs7 -inform DER -in .../lenovofnandfunctionkeys.cat -print_certs -noout` to confirm the embedded evidence.",
  "hardware_touched": false,
  "other_files_modified": false
}