// Ghidra headless script: dump RTTI/vtable symbols for CMoniter* classes and their targets.
// Usage: -process <bin> -noanalysis -scriptPath <dir> -postScript DumpVtables.java <outDir>
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import java.io.*;

public class DumpVtables extends GhidraScript {
    @Override
    public void run() throws Exception {
        File dir = new File(getScriptArgs()[0]);
        PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter(new File(dir, "vtables.txt"))));
        Program prog = currentProgram;
        Memory mem = prog.getMemory();
        SymbolTable st = prog.getSymbolTable();
        FunctionManager fm = prog.getFunctionManager();
        w.println("# Symbols matching CMoniter / vftable / RTTI");
        java.util.List<Symbol> vsyms = new java.util.ArrayList<>();
        for (Symbol s : st.getAllSymbols(true)) {
            String n = s.getName(true);
            if (n.contains("CMoniter") || n.toLowerCase().contains("vftable") || n.contains("RTTI")) {
                w.println("SYM  " + s.getAddress() + "  " + n + "  type=" + s.getSymbolType());
                if (n.toLowerCase().contains("vftable")) vsyms.add(s);
            }
        }
        DecompInterface ifc = new DecompInterface();
        ifc.toggleCCode(true);
        ifc.setSimplificationStyle("decompile");
        ifc.openProgram(prog);
        PrintWriter d = new PrintWriter(new BufferedWriter(new FileWriter(new File(dir, "vtables-decompile.txt"))));
        for (Symbol s : vsyms) {
            Address a = s.getAddress();
            w.println("\n== VTABLE " + s.getName(true) + " @ " + a);
            for (int i = 0; i < 8; i++) {
                Address e = a.add(i * 8L);
                long v;
                try {
                    v = mem.getLong(e);
                } catch (Exception ex) { break; }
                Address t = toAddr(v);
                Function f = fm.getFunctionAt(t);
                w.printf("   [%d] +0x%02x -> %s  %s%n", i, i * 8, t,
                        f == null ? "" : f.getName(true));
                if (f != null) {
                    d.printf("%n/* ==== %s  @ %s (%d bytes)  [vtable %s slot %d] ==== */%n",
                            f.getName(true), f.getEntryPoint(), f.getBody().getNumAddresses(), s.getName(true), i);
                    DecompileResults r = ifc.decompileFunction(f, 120, monitor);
                    d.println(r != null && r.decompileCompleted() ? r.getDecompiledFunction().getC()
                            : "// FAILED " + (r == null ? "null" : r.getErrorMessage()));
                }
            }
        }
        d.close();
        w.close();
        println("done");
    }
}
