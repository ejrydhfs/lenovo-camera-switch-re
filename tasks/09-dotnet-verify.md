# Task 09: finish the Windows-package deliverables with real tooling
$W = /home/user/Downloads/lenovo-camera-switch-re
A prior read-only scout produced metadata-accurate but unverified findings (no shell tool available to it):
  - blurswitchcs.dll = .NET 4.6.1 assembly, class `BlurSwitchCS`, methods ToggleBlurSwitch/SendMessageAsync/OpenAsync,
    status constants STATUS_SET_BLUR_OFF_OK / STATUS_SET_BLUR_ON_OK / STATUS_EXCEPTION / STATUS_SVR_REPOND_ERR /
    STATUS_SET_FEATURE_ERR / STATUS_RETURN_ERR / STATUS_CONNECT_SVR_ERR / STATUS_SET_TIMEOUT,
    literals "Key","ToggleBlurSwitch","Result","BlurOff","BlurOn","BlurError";
    connects to AppService `Lenovo.CameraControlBackgroundService` in UWP family `E0469640.SmartAppearance_5grkq8ppsgwt4`.
  - package has NO .sys; INF ServiceBinary = %13%\LenovoUtilityService.exe; cat signed by MS WHCP.
Your job: VERIFY these with real tools and write the final files. Nothing may be taken on trust.
1. `dotnet tool install -g ilspycmd` (network works) then
   `~/.dotnet/tools/ilspycmd -t BlurSwitchCS "<$W/10-extracted/code\$getextractpath\$/source/blurswitchcs.dll>"`
   (quote the path; it contains a literal $). If ilspycmd is unavailable, use `dotnet` + a decompiler-free approach
   (monodis is absent; you may install `ilspycmd`, or parse with python `pefile` metadata + IL bytes) - but state exactly
   which tool produced the output.
   Write the result to $W/10-extracted/analysis/blurswitchcs.decompiled.cs with the exact command used in a header comment.
2. Confirm/refute with grep over $W/70-evidence/strings-*.txt:
   - which binary contains `E046963F.LenovoCompanion_k1h2ywk1493x8` and `E0469640.LenovoUtility_5grkq8ppsgwt4!LenovoUtility`
   - the AppService name string present in blurswitchcs.dll
3. Write $W/10-extracted/analysis/WINDOWS-STACK.md : the complete Windows architecture (INF -> auto-start service
   -> worker in user session -> WMI event subscription -> camera-switch decode -> UWP AppService for blur),
   per-file role table for every payload file, and the signature/catalogue facts.
   Include verbatim command output as evidence.
4. Explicitly answer with citations: does ANY component in this package READ the camera switch state, or does the
   package only react to the WMI event / only toggle software blur and Windows camera privacy?
Deliverables: the two files above. Do NOT modify anything else. Do NOT touch hardware (read-only).
