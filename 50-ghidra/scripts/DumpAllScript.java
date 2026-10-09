// Dump decompilation, imports, strings and xrefs for the current program.
// Usage: -postScript DumpAllScript.java <outdir> <tag>
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import java.io.*;
import java.util.*;

public class DumpAllScript extends GhidraScript {

    private PrintWriter open(String dir, String name) throws IOException {
        return new PrintWriter(new BufferedWriter(new FileWriter(new File(dir, name))));
    }

    private String hex(long v) { return String.format("0x%08x", v); }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outdir = args.length > 0 ? args[0] : "/tmp";
        String tag = args.length > 1 ? args[1] : "prog";
        new File(outdir).mkdirs();

        // memory blocks
        PrintWriter mb = open(outdir, tag + "-blocks.txt");
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            mb.println(String.format("%s %s-%s size=0x%x r=%b w=%b x=%b init=%b",
                b.getName(), b.getStart(), b.getEnd(), b.getSize(), b.isRead(), b.isWrite(), b.isExecute(), b.isInitialized()));
        }
        mb.close();

        // imports / external symbols
        PrintWriter imp = open(outdir, tag + "-imports.txt");
        SymbolTable st = currentProgram.getSymbolTable();
        for (Symbol s : st.getExternalSymbols()) {
            imp.println(s.getName() + "  parent=" + s.getParentNamespace().getName());
        }
        imp.close();

        // thunk -> external mapping
        PrintWriter th = open(outdir, tag + "-thunks.txt");
        FunctionManager fm = currentProgram.getFunctionManager();
        for (Function f : fm.getFunctions(true)) {
            if (f.isThunk()) {
                th.println(f.getEntryPoint() + " " + f.getName() + " thunked=" + (f.getThunkedFunction(true) != null ? f.getThunkedFunction(true).getName() : "?"));
            }
        }
        th.close();

        // functions + decompilation
        DecompInterface ifc = new DecompInterface();
        ifc.toggleCCode(true);
        ifc.toggleSyntaxTree(false);
        ifc.setSimplificationStyle("decompile");
        if (!ifc.openProgram(currentProgram)) {
            println("decompiler open failed");
        }
        PrintWriter dec = open(outdir, tag + "-decomp.c");
        PrintWriter idx = open(outdir, tag + "-functions.txt");
        int n = 0, fails = 0;
        for (Function f : fm.getFunctions(true)) {
            if (f.isThunk() || f.isExternal()) continue;
            idx.println(String.format("%s %s size=%d params=%d", f.getEntryPoint(), f.getName(), f.getBody().getNumAddresses(), f.getParameterCount()));
            DecompileResults res = ifc.decompileFunction(f, 60, monitor);
            dec.println("//===== " + f.getEntryPoint() + " " + f.getName() + " =====");
            if (res != null && res.decompileCompleted()) {
                dec.println(res.getDecompiledFunction().getC());
            } else {
                dec.println("// DECOMP FAILED: " + (res != null ? res.getErrorMessage() : "null"));
                fails++;
            }
            n++;
        }
        dec.close();
        idx.close();
        ifc.dispose();

        // defined strings with xrefs
        PrintWriter strs = open(outdir, tag + "-strings-xref.txt");
        Listing lst = currentProgram.getListing();
        DataIterator di = lst.getDefinedData(true);
        while (di.hasNext()) {
            Data d = di.next();
            if (d == null) continue;
            String t = d.getDataType().getName().toLowerCase();
            if (t.contains("string") || t.contains("unicode")) {
                Object v = d.getValue();
                if (v == null) continue;
                String sv = v.toString().replace("\n", "\\n").replace("\r", "\\r");
                if (sv.length() > 300) sv = sv.substring(0, 300) + "...";
                strs.println(d.getAddress() + " | " + sv);
                ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(d.getAddress());
                while (ri.hasNext()) {
                    Reference r = ri.next();
                    strs.println("      xref " + r.getFromAddress() + " " + r.getReferenceType() + " in " + funcAt(r.getFromAddress()));
                }
            }
        }
        strs.close();
        println("DUMP DONE functions=" + n + " decompFails=" + fails);
    }

    private String funcAt(Address a) {
        Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
        return f == null ? "?" : (f.getName() + "@" + f.getEntryPoint());
    }
}
