// Ghidra headless script: dump symbols, string refs, decompilation for named/target functions.
// Usage: -postScript DumpFnHotkey.java <outDir>
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;
import java.io.*;
import java.util.*;

public class DumpFnHotkey extends GhidraScript {

    PrintWriter out(String name) throws Exception {
        File dir = new File(getScriptArgs()[0]);
        dir.mkdirs();
        return new PrintWriter(new BufferedWriter(new FileWriter(new File(dir, name))));
    }

    static final String[] TOKENS = {
        "CAMERA", "e_Event_", "SwitchCameraStatus", "SELECT * FROM", "LSK", "FnQ",
        "CameraPrivacy", "UtilityEvent", "Win32_", "Root\\\\WMI", "ROOT\\\\WMI", "BMOF",
        "Microsoft_", "LSKEvent", "LENOVO_", "WMI", "camera", "Camera", "CAMS", "CAM_",
        "camera_power", "Blur", "FnLock", "KeyEvent", "HotKey", "hotkey"
    };

    static final String[] NAME_PATTERNS = {
        "MsgLogic", "Moniter", "Monitor", "Camera", "camera", "Wmi", "WMI",
        "Switch", "switch", "UtilityEvent", "FnQ", "WMIMonitor", "Blur"
    };

    boolean matchesTokens(String s) {
        for (String t : TOKENS) {
            if (s.contains(t)) return true;
        }
        return false;
    }

    @Override
    public void run() throws Exception {
        Program prog = currentProgram;
        Memory mem = prog.getMemory();
        Listing listing = prog.getListing();
        FunctionManager fm = prog.getFunctionManager();
        ReferenceManager rm = prog.getReferenceManager();

        // ---------- Section A: all functions ----------
        PrintWriter a = out("symbols.txt");
        a.println("# All functions: addr  size  name");
        int nf = 0;
        for (Function f : fm.getFunctions(true)) {
            a.printf("%s\t%d\t%s%n", f.getEntryPoint(), f.getBody().getNumAddresses(), f.getName(true));
            nf++;
        }
        a.println("# total functions: " + nf);
        a.close();

        // ---------- Section B: string refs ----------
        PrintWriter b = out("stringrefs.txt");
        b.println("# Interesting strings and their references (token filter)");
        Map<Address, String> hits = new LinkedHashMap<>();
        DataIterator di = listing.getDefinedData(true);
        int nstr = 0;
        while (di.hasNext()) {
            Data d = di.next();
            if (!d.hasStringValue()) continue;
            Object v = d.getValue();
            if (!(v instanceof String)) continue;
            String s = (String) v;
            if (s.length() < 3) continue;
            nstr++;
            if (!matchesTokens(s)) continue;
            hits.put(d.getAddress(), s);
        }
        b.println("# total defined strings scanned: " + nstr + ", token hits: " + hits.size());
        Set<Function> targetFns = new LinkedHashSet<>();
        for (Map.Entry<Address, String> e : hits.entrySet()) {
            Address saddr = e.getKey();
            String pretty = e.getValue().replace("\n", "\\n").replace("\r", "\\r");
            b.printf("\n== %s  \"%s\"%n", saddr, pretty);
            ReferenceIterator ri = rm.getReferencesTo(saddr);
            boolean any = false;
            while (ri.hasNext()) {
                Reference r = ri.next();
                Function cf = fm.getFunctionContaining(r.getFromAddress());
                b.printf("    from %s  type=%s  func=%s%n", r.getFromAddress(), r.getReferenceType(),
                        cf == null ? "<none>" : cf.getName(true) + "@" + cf.getEntryPoint());
                if (cf != null) targetFns.add(cf);
                any = true;
            }
            if (!any) b.println("    (no references)");
        }
        b.close();

        // ---------- Section C: named-pattern functions ----------
        Set<Function> namedFns = new LinkedHashSet<>();
        for (Function f : fm.getFunctions(true)) {
            String n = f.getName(true);
            for (String p : NAME_PATTERNS) {
                if (n.contains(p)) { namedFns.add(f); break; }
            }
        }
        PrintWriter cn = out("named-functions.txt");
        cn.println("# Functions whose symbol name matches interesting patterns");
        for (Function f : namedFns) {
            cn.printf("%s\t%d\t%s%n", f.getEntryPoint(), f.getBody().getNumAddresses(), f.getName(true));
        }
        cn.close();

        // ---------- Section D: decompile everything in targetFns U namedFns ----------
        Set<Function> all = new LinkedHashSet<>();
        all.addAll(targetFns);
        all.addAll(namedFns);
        DecompInterface ifc = new DecompInterface();
        ifc.toggleCCode(true);
        ifc.toggleSyntaxTree(false);
        ifc.setSimplificationStyle("decompile");
        DecompileOptions opts = new DecompileOptions();
        ifc.setOptions(opts);
        if (!ifc.openProgram(prog)) {
            println("decompiler open failed");
        }
        PrintWriter c = out("decompile.txt");
        PrintWriter dsc = out("disasm-named.txt");
        int done = 0;
        for (Function f : all) {
            c.printf("%n/* ================================================================%n");
            c.printf("   FUNCTION %s  @ %s  size=%d%n", f.getName(true), f.getEntryPoint(), f.getBody().getNumAddresses());
            c.printf("   signature: %s%n", f.getPrototypeString(true, true));
            c.printf("   ================================================================ */%n");
            try {
                DecompileResults res = ifc.decompileFunction(f, 120, monitor);
                if (res != null && res.decompileCompleted()) {
                    c.println(res.getDecompiledFunction().getC());
                } else {
                    c.println("// DECOMPILE FAILED: " + (res == null ? "null" : res.getErrorMessage()));
                }
            } catch (Throwable t) {
                c.println("// DECOMPILE EXCEPTION: " + t);
            }
            done++;
            if (done % 25 == 0) println("decompiled " + done + "/" + all.size());
        }
        c.close();

        // ---------- Section E: disassembly of named functions ----------
        for (Function f : namedFns) {
            dsc.printf("%n==== %s @ %s (%d bytes) ====%n", f.getName(true), f.getEntryPoint(), f.getBody().getNumAddresses());
            InstructionIterator ii = listing.getInstructions(f.getBody(), true);
            while (ii.hasNext()) {
                Instruction ins = ii.next();
                dsc.printf("%s  %s%n", ins.getAddress(), ins.toString());
            }
        }
        dsc.close();

        println("TARGET functions: stringRefs=" + targetFns.size() + " named=" + namedFns.size() + " total=" + all.size());
    }
}
