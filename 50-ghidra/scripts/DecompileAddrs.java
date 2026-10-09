// Ghidra headless script: decompile a list of addresses given on the command line.
// Usage: -postScript DecompileAddrs.java <outFile> <addr> [<addr> ...]
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class DecompileAddrs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter(new File(args[0]))));
        DecompInterface ifc = new DecompInterface();
        ifc.toggleCCode(true);
        ifc.setSimplificationStyle("decompile");
        ifc.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        for (int i = 1; i < args.length; i++) {
            String s = args[i];
            boolean name = false;
            if (s.startsWith("@")) { name = true; s = s.substring(1); }
            Function f = null;
            if (name) {
                for (Function cand : fm.getFunctions(true)) {
                    if (cand.getName(true).equals(s)) { f = cand; break; }
                }
            } else {
                f = fm.getFunctionContaining(toAddr(Long.parseLong(s, 16)));
            }
            w.printf("%n/* ================================================================%n");
            w.printf("   FUNCTION %s  @ %s  size=%d%n", f == null ? "NOTFOUND(" + s + ")" : f.getName(true),
                    f == null ? "?" : f.getEntryPoint().toString(),
                    f == null ? 0 : f.getBody().getNumAddresses());
            w.printf("   signature: %s%n", f == null ? "" : f.getPrototypeString(true, true));
            w.printf("   ================================================================ */%n");
            if (f != null) {
                DecompileResults r = ifc.decompileFunction(f, 180, monitor);
                w.println(r != null && r.decompileCompleted() ? r.getDecompiledFunction().getC()
                        : "// FAILED " + (r == null ? "null" : r.getErrorMessage()));
            }
        }
        w.close();
        println("wrote " + args[0]);
    }
}
