import com.android.tools.smali.dexlib2.*;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedMethodImplementation;
import com.android.tools.smali.dexlib2.iface.*;
import com.android.tools.smali.dexlib2.iface.instruction.*;
import com.android.tools.smali.dexlib2.iface.instruction.formats.ArrayPayload;
import com.android.tools.smali.dexlib2.iface.reference.*;
import java.io.File;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Read-only, typed array-payload/decoder inspection. No target names or offsets. */
public final class StartupDex {
    static String name(MethodReference m) {
        StringBuilder s = new StringBuilder(m.getDefiningClass()).append("->").append(m.getName()).append('(');
        for (CharSequence p : m.getParameterTypes()) s.append(p);
        return s.append(')').append(m.getReturnType()).toString();
    }
    static void row(String... values) {
        StringJoiner line = new StringJoiner("\t");
        for (String v : values) line.add(Base64.getEncoder().encodeToString(v.getBytes(StandardCharsets.UTF_8)));
        System.out.println(line);
    }
    static List<Integer> registers(Instruction i) {
        List<Integer> r = new ArrayList<>();
        if (i instanceof FiveRegisterInstruction) {
            FiveRegisterInstruction f = (FiveRegisterInstruction)i;
            int[] all = {f.getRegisterC(), f.getRegisterD(), f.getRegisterE(), f.getRegisterF(), f.getRegisterG()};
            for (int j = 0; j < f.getRegisterCount(); j++) r.add(all[j]);
        } else if (i instanceof RegisterRangeInstruction) {
            RegisterRangeInstruction f = (RegisterRangeInstruction)i;
            for (int j = 0; j < f.getRegisterCount(); j++) r.add(f.getStartRegister() + j);
        }
        return r;
    }
    public static void main(String[] args) throws Exception {
        Opcodes opcodes = Opcodes.forApi(Integer.parseInt(args[0]));
        Map<String, Method> methods = new HashMap<>();
        List<File> files = new ArrayList<>();
        File[] found = new File(args[1]).listFiles((d, n) -> n.matches("classes(?:[2-9]|[1-9][0-9]+)?\\.dex"));
        if (found == null) throw new IllegalArgumentException("Missing DEX directory");
        files.addAll(Arrays.asList(found)); files.sort(Comparator.comparing(File::getName));
        for (File file : files) for (ClassDef c : DexFileFactory.loadDexFile(file, opcodes).getClasses())
            for (Method m : c.getMethods()) if (methods.put(name(m), m) != null)
                throw new IllegalArgumentException("Duplicate method definition: " + name(m));
        Field code = DexBackedMethodImplementation.class.getDeclaredField("codeOffset"); code.setAccessible(true);
        int candidates = 0;
        for (File file : files) for (ClassDef c : DexFileFactory.loadDexFile(file, opcodes).getClasses()) {
            for (Method m : c.getMethods()) {
                MethodImplementation impl = m.getImplementation(); if (impl == null) continue;
                Map<Integer, Instruction> instructions = new LinkedHashMap<>(); int pc = 0;
                for (Instruction i : impl.getInstructions()) { instructions.put(pc, i); pc += i.getCodeUnits(); }
                for (Map.Entry<Integer, Instruction> entry : instructions.entrySet()) {
                    Instruction fill = entry.getValue(); if (fill.getOpcode() != Opcode.FILL_ARRAY_DATA) continue;
                    int target = entry.getKey() + ((OffsetInstruction)fill).getCodeOffset();
                    Instruction data = instructions.get(target);
                    if (!(data instanceof ArrayPayload)) throw new IllegalArgumentException("Invalid array target");
                    ArrayPayload payload = (ArrayPayload)data;
                    if (payload.getElementWidth() != 2 || payload.getArrayElements().size() != 64) continue;
                    if (++candidates > 4096) throw new IllegalArgumentException("64-character payload budget exceeded");
                    int arrayRegister = ((OneRegisterInstruction)fill).getRegisterA();
                    Set<Integer> aliases = new HashSet<>(); aliases.add(arrayRegister);
                    Set<String> decoders = new TreeSet<>(); boolean stringArray = false;
                    // Local def-use only: stop at a branch, register overwrite, or 48 code units.
                    for (Map.Entry<Integer, Instruction> use : instructions.entrySet()) {
                        int at = use.getKey(); if (at <= entry.getKey() || at > entry.getKey() + 48) continue;
                        Instruction i = use.getValue(); String op = i.getOpcode().name;
                        if (op.startsWith("if-") || op.startsWith("goto") || op.endsWith("switch")) break;
                        if (i instanceof ReferenceInstruction) {
                            Reference ref = ((ReferenceInstruction)i).getReference();
                            if (ref instanceof TypeReference && ((TypeReference)ref).getType().equals("[Ljava/lang/String;"))
                                stringArray = true;
                            if (ref instanceof MethodReference && op.startsWith("invoke-static")) {
                                MethodReference call = (MethodReference)ref; List<Integer> regs = registers(i);
                                int parameterRegister = 0;
                                for (CharSequence p : call.getParameterTypes()) {
                                    if (p.toString().equals("[C") && parameterRegister < regs.size() && aliases.contains(regs.get(parameterRegister)))
                                        decoders.add(name(call));
                                    parameterRegister += p.toString().equals("J") || p.toString().equals("D") ? 2 : 1;
                                }
                            }
                        }
                        if (i.getOpcode().setsRegister() && i instanceof OneRegisterInstruction) {
                            int dest = ((OneRegisterInstruction)i).getRegisterA();
                            boolean copy = op.startsWith("move-object") && i instanceof TwoRegisterInstruction
                                && aliases.contains(((TwoRegisterInstruction)i).getRegisterB());
                            aliases.remove(dest); if (copy) aliases.add(dest);
                        }
                    }
                    StringJoiner values = new StringJoiner(",");
                    for (Number v : payload.getArrayElements()) values.add(Integer.toString(v.intValue() & 65535));
                    for (String decoder : decoders) {
                        Method method = methods.get(decoder); if (method == null || method.getImplementation() == null) continue;
                        boolean readsChars = false, buildsString = false;
                        for (Instruction i : method.getImplementation().getInstructions()) {
                            if (i.getOpcode() == Opcode.AGET_CHAR) readsChars = true;
                            if (i instanceof ReferenceInstruction && ((ReferenceInstruction)i).getReference() instanceof MethodReference) {
                                String ref = name((MethodReference)((ReferenceInstruction)i).getReference());
                                if (ref.equals("Ljava/lang/String;-><init>([C)V")) buildsString = true;
                            }
                        }
                        int offset = code.getInt(impl) + 16 + 2 * target + 8;
                        row(file.getName(), name(m), Integer.toString(offset), values.toString(), decoder,
                            Boolean.toString(readsChars), Boolean.toString(buildsString), Boolean.toString(stringArray));
                    }
                }
            }
        }
    }
}
