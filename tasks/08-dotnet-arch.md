# Task 08: Windows package architecture + .NET decompile
Payload dir: $W/10-extracted/code$getextractpath$/source/   ($W=/home/user/Downloads/lenovo-camera-switch-re)
1. Decompile `blurswitchcs.dll` (PE32, .NET/CIL, 15 KB). `dotnet` is installed on the host; install the decompiler with
   `dotnet tool install -g ilspycmd` (network available) or `dotnet tool run`. Dump the full C# of class `BlurSwitchCS`
   (methods: ToggleBlurSwitch, SendMessageAsync, OpenAsync) into $W/10-extracted/analysis/blurswitchcs.decompiled.cs.
   Report: the AppService name / package family name it connects to, the exact request keys/values it sends and the
   status codes (STATUS_SET_BLUR_ON_OK etc.).
2. Also inspect `dpinst.xml`, `lenovofnandfunctionkeys.cat` (signature: use `openssl pkcs7 -inform DER -print_certs`),
   and confirm/refute the presence of any kernel-mode `.sys` driver in the package. Document the full Windows stack
   and data flow (INF -> service -> worker -> UWP AppService -> OSD) in $W/10-extracted/analysis/WINDOWS-STACK.md.
3. Grep `ludp.dll`, `ludp.net.dll`, `controllib.dll`, `intelcontrollib.dll`, `atiadlxx.dll` string dumps in
   $W/70-evidence/ for anything camera/privacy/blur/LVF/smartappearance related and for the AppService name
   `E0469640.LenovoUtility_5grkq8ppsgwt4!LenovoUtility` and `E046963F.LenovoCompanion_k1h2ywk1493x8`; report what
   each package is and which component owns the camera/blur feature.
4. Explicitly answer: is the camera *switch state* ever read by these binaries, or do they only *toggle* blur?
   Cite evidence (string or decompiled line). Mark [INFERENCE] where needed.
Acceptance: WINDOWS-STACK.md + blurswitchcs.decompiled.cs exist and answer 1-4 with citations.
