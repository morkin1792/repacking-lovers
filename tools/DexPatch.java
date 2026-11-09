import com.android.tools.smali.dexlib2.*;
import com.android.tools.smali.dexlib2.iface.*;
import com.android.tools.smali.dexlib2.iface.instruction.*;
import com.android.tools.smali.dexlib2.iface.reference.*;
import com.android.tools.smali.dexlib2.immutable.*;
import com.android.tools.smali.dexlib2.immutable.instruction.*;
import com.android.tools.smali.dexlib2.immutable.reference.*;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Typed DEX inspection and complete-class copying. Selection stays in the Python matcher. */
public final class DexPatch {
    static String methodName(MethodReference method) {
        StringBuilder result = new StringBuilder(method.getName()).append('(');
        for (CharSequence type : method.getParameterTypes()) result.append(type);
        return result.append(')').append(method.getReturnType()).toString();
    }
    static String encoded(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
    static void row(String... values) {
        for (int i = 0; i < values.length; i++) {
            if (i != 0) System.out.print('\t');
            System.out.print(encoded(values[i]));
        }
        System.out.println();
    }
    static List<File> dexFiles(File directory) {
        File[] files = directory.listFiles((parent, name) -> name.matches("classes(?:[2-9]|[1-9][0-9]+)?\\.dex"));
        if (files == null || files.length == 0) throw new IllegalArgumentException("Missing original DEX files");
        List<File> result = Arrays.asList(files);
        result.sort(Comparator.comparingInt(file -> file.getName().equals("classes.dex") ? 1
                : Integer.parseInt(file.getName().substring(7, file.getName().length() - 4))));
        for (int i = 0; i < result.size(); i++) {
            String expected = i == 0 ? "classes.dex" : "classes" + (i + 1) + ".dex";
            if (!result.get(i).getName().equals(expected)) throw new IllegalArgumentException("Non-contiguous DEX files");
        }
        return result;
    }
    static void inspect(File directory, Opcodes opcodes) throws Exception {
        for (File dex : dexFiles(directory)) {
            DexFile file = DexFileFactory.loadDexFile(dex, opcodes);
            for (ClassDef cls : file.getClasses()) {
                List<String> fieldTypes = new ArrayList<>();
                for (Field field : cls.getFields()) fieldTypes.add(field.getType());
                Collections.sort(fieldTypes);
                row("class", dex.getName(), cls.getType(), cls.getSuperclass() == null ? "" : cls.getSuperclass(),
                    String.join(",", cls.getInterfaces()), Integer.toString(cls.getAccessFlags()), String.join(",", fieldTypes));
                for (Method method : cls.getMethods()) {
                    TreeSet<String> strings = new TreeSet<>(), references = new TreeSet<>();
                    TreeSet<String> literals = new TreeSet<>();
                    MethodImplementation implementation = method.getImplementation();
                    if (implementation != null) for (Instruction instruction : implementation.getInstructions()) {
                        if (instruction instanceof WideLiteralInstruction)
                            literals.add(Long.toString(((WideLiteralInstruction) instruction).getWideLiteral()));
                        if (instruction instanceof ReferenceInstruction) {
                            Reference reference = ((ReferenceInstruction) instruction).getReference();
                            if (reference instanceof StringReference) strings.add(((StringReference) reference).getString());
                            else if (reference instanceof MethodReference) {
                                MethodReference ref = (MethodReference) reference;
                                references.add(ref.getDefiningClass() + "->" + methodName(ref));
                            } else if (reference instanceof TypeReference) references.add(((TypeReference) reference).getType());
                            else if (reference instanceof FieldReference) {
                                FieldReference ref = (FieldReference) reference;
                                references.add(ref.getDefiningClass() + "->" + ref.getName() + ":" + ref.getType());
                            }
                        }
                    }
                    // Individual base64 fields keep arbitrary target strings out of the line protocol.
                    row("method", cls.getType(), methodName(method), Integer.toString(method.getAccessFlags()),
                        implementation == null ? "absent" : "present", String.join("\u0000", strings), String.join("\u0000", references), String.join(",", literals));
                }
            }
        }
    }
    static ImmutableMethod patched(Method method, String replacement) {
        if (method.getImplementation() == null || (method.getAccessFlags() & (0x100 | 0x400)) != 0)
            throw new IllegalArgumentException("Cannot patch native/abstract method");
        if (method.getName().startsWith("<")) throw new IllegalArgumentException("Cannot patch constructor/class initializer");
        String result = method.getReturnType();
        if (replacement.equals("conscrypt-server-trust")) return conscryptPatched(method);
        if (!(replacement.equals("return-void") && result.equals("V"))
                && !((replacement.equals("return-true") || replacement.equals("return-false")) && result.equals("Z"))
                && !(replacement.equals("return-empty-list") && result.equals("Ljava/util/List;")
                    && method.getDefiningClass().equals("Lorg/chromium/net/impl/CronetEngineBuilderImpl;")
                    && methodName(method).equals("publicKeyPins()Ljava/util/List;"))
                && !(replacement.equals("interceptor-proceed") && result.equals("Lokhttp3/Response;")
                    && method.getParameterTypes().size() == 1
                    && method.getParameterTypes().get(0).toString().equals("Lokhttp3/Interceptor$Chain;")
                    && (method.getAccessFlags() & 8) == 0))
            throw new IllegalArgumentException("Replacement/descriptor contract mismatch: " + replacement);
        int parameters = (method.getAccessFlags() & 8) == 0 ? 1 : 0;
        for (CharSequence parameter : method.getParameterTypes())
            parameters += parameter.toString().equals("J") || parameter.toString().equals("D") ? 2 : 1;
        List<Instruction> instructions = new ArrayList<>();
        instructions.add(new ImmutableInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference("REPACK_PATCH")));
        instructions.add(new ImmutableInstruction21c(Opcode.CONST_STRING, 1,
                new ImmutableStringReference(method.getDefiningClass() + "->" + methodName(method))));
        instructions.add(new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 2, 0, 1, 0, 0, 0,
                new ImmutableMethodReference("Landroid/util/Log;", "i", Arrays.asList("Ljava/lang/String;", "Ljava/lang/String;"), "I")));
        if (replacement.equals("interceptor-proceed")) {
            // Two scratch registers precede `this` and `chain`; logging cannot
            // overwrite the parameter. Return the real response and propagate
            // proceed's exception normally, with no obsolete catch ranges.
            int chain = 3;
            instructions.add(new ImmutableInstruction35c(Opcode.INVOKE_INTERFACE, 1, chain, 0, 0, 0, 0,
                new ImmutableMethodReference("Lokhttp3/Interceptor$Chain;", "request", Collections.emptyList(), "Lokhttp3/Request;")));
            instructions.add(new ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1));
            instructions.add(new ImmutableInstruction35c(Opcode.INVOKE_INTERFACE, 2, chain, 1, 0, 0, 0,
                new ImmutableMethodReference("Lokhttp3/Interceptor$Chain;", "proceed", Arrays.asList("Lokhttp3/Request;"), "Lokhttp3/Response;")));
            instructions.add(new ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
            instructions.add(new ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0));
        }
        else if (replacement.equals("return-empty-list")) {
            instructions.add(new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Ljava/util/Collections;", "emptyList", Collections.emptyList(), "Ljava/util/List;")));
            instructions.add(new ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
            instructions.add(new ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0));
        }
        else if (result.equals("V")) instructions.add(new ImmutableInstruction10x(Opcode.RETURN_VOID));
        else {
            instructions.add(new ImmutableInstruction11n(Opcode.CONST_4, 0, replacement.equals("return-true") ? 1 : 0));
            instructions.add(new ImmutableInstruction11x(Opcode.RETURN, 0));
        }
        MethodImplementation body = new ImmutableMethodImplementation(parameters + 2, instructions,
                Collections.emptyList(), Collections.emptyList());
        return new ImmutableMethod(method.getDefiningClass(), method.getName(), method.getParameters(),
                method.getReturnType(), method.getAccessFlags(), method.getAnnotations(), method.getHiddenApiRestrictions(), body);
    }
    static ImmutableMethod conscryptPatched(Method method) {
        // Conscrypt records the negotiated chain in this callback. A return-void
        // stub loses peer certificates and can break OkHttp after a successful
        // handshake. Keep parsing/session updates, and remove only the audited
        // server trust call. Equal code-unit lengths preserve branches/handlers.
        String owner = method.getDefiningClass();
        if (!(owner.equals("Lorg/conscrypt/ConscryptEngine;") || owner.equals("Lorg/conscrypt/ConscryptFileDescriptorSocket;")
                || owner.equals("Lcom/google/android/gms/org/conscrypt/ConscryptEngine;")
                || owner.equals("Lcom/google/android/gms/org/conscrypt/ConscryptFileDescriptorSocket;"))
                || !methodName(method).equals("verifyCertificateChain([[BLjava/lang/String;)V")
                || (method.getAccessFlags() & 8) != 0)
            throw new IllegalArgumentException("Conscrypt callback contract mismatch");
        String platform = owner.substring(0, owner.lastIndexOf('/') + 1) + "Platform;";
        List<Instruction> instructions = new ArrayList<>(); int removed = 0;
        for (Instruction i : method.getImplementation().getInstructions()) {
            MethodReference ref = i instanceof ReferenceInstruction && ((ReferenceInstruction)i).getReference() instanceof MethodReference
                ? (MethodReference)((ReferenceInstruction)i).getReference() : null;
            if (ref != null && i.getOpcode().name.startsWith("invoke-static") && ref.getDefiningClass().equals(platform)
                    && ref.getName().equals("checkServerTrusted") && ref.getReturnType().equals("V")
                    && ref.getParameterTypes().size() == 4
                    && ref.getParameterTypes().get(0).toString().equals("Ljavax/net/ssl/X509TrustManager;")
                    && ref.getParameterTypes().get(1).toString().equals("[Ljava/security/cert/X509Certificate;")
                    && ref.getParameterTypes().get(2).toString().equals("Ljava/lang/String;")
                    && Arrays.asList("Ljavax/net/ssl/SSLEngine;", "Ljava/net/Socket;",
                        owner.substring(0, owner.lastIndexOf('/') + 1) + "ConscryptEngine;",
                        owner.substring(0, owner.lastIndexOf('/') + 1) + "AbstractConscryptSocket;")
                        .contains(ref.getParameterTypes().get(3).toString())) {
                for (int j = 0; j < i.getCodeUnits(); j++) instructions.add(new ImmutableInstruction10x(Opcode.NOP));
                removed++;
            } else instructions.add(ImmutableInstruction.of(i));
        }
        if (removed != 1) throw new IllegalArgumentException("Expected one unambiguous Conscrypt server-trust call, found " + removed);
        MethodImplementation old = method.getImplementation();
        MethodImplementation body = new ImmutableMethodImplementation(old.getRegisterCount(), instructions, old.getTryBlocks(), old.getDebugItems());
        return new ImmutableMethod(owner, method.getName(), method.getParameters(), method.getReturnType(), method.getAccessFlags(),
                method.getAnnotations(), method.getHiddenApiRestrictions(), body);
    }
    static ImmutableMethod chromiumPatched(Method method, Map<String, ClassDef> classes, byte[] anchor,
                                           Map<String, ClassDef> helpers) throws Exception {
        String result = "Lorg/chromium/net/AndroidCertVerifyResult;";
        String signature = methodName(method);
        if (!method.getDefiningClass().equals("Lorg/chromium/net/AndroidNetworkLibrary;")
                || !(signature.equals("verifyServerCertificates([[BLjava/lang/String;Ljava/lang/String;)" + result)
                    || signature.equals("verifyServerCertificates([[BLjava/lang/String;Ljava/lang/String;[B[B)" + result))
                || (method.getAccessFlags() & 9) != 9 || method.getImplementation() == null || anchor == null)
            throw new IllegalArgumentException("Chromium verifier/anchor contract mismatch");
        java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate)
            java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(anchor));
        if (cert.getBasicConstraints() < 0 || !Arrays.equals(cert.getEncoded(), anchor) || anchor.length > 16000)
            throw new IllegalArgumentException("Chromium requires one DER CA certificate");
        Map<String, MethodReference> callees = new LinkedHashMap<>();
        for (Instruction instruction : method.getImplementation().getInstructions()) {
            if (!(instruction instanceof ReferenceInstruction) || !instruction.getOpcode().name.startsWith("invoke-static")) continue;
            Reference reference = ((ReferenceInstruction)instruction).getReference();
            if (!(reference instanceof MethodReference)) continue;
            MethodReference target = (MethodReference)reference;
            if (!target.getReturnType().equals(result) || !target.getParameterTypes().equals(method.getParameterTypes())
                    || target.getDefiningClass().equals(method.getDefiningClass())) continue;
            ClassDef owner = classes.get(target.getDefiningClass());
            if (owner == null || (owner.getAccessFlags() & 1) == 0) continue;
            boolean inner = false, addRoot = false;
            for (Method member : owner.getMethods()) {
                if (member.getImplementation() == null || (member.getAccessFlags() & 9) != 9) continue;
                if (methodName(member).equals(methodName(target))) inner = true;
                if (methodName(member).equals("addTestRootCertificate([B)V")) addRoot = true;
            }
            if (inner && addRoot) callees.put(target.toString(), target);
        }
        if (callees.size() != 1) throw new IllegalArgumentException("Missing/ambiguous owned Chromium helper");
        MethodReference target = callees.values().iterator().next();
        String digest = Base64.getUrlEncoder().withoutPadding().encodeToString(
            java.security.MessageDigest.getInstance("SHA-256").digest((target.getDefiningClass() + Base64.getEncoder().encodeToString(anchor)).getBytes(StandardCharsets.UTF_8)));
        String helper = "Ldev/repack/tls/Anchor_" + digest.replace('-', '_') + ";";
        if (classes.containsKey(helper)) throw new IllegalArgumentException("Chromium anchor class collision");
        if (!helpers.containsKey(helper)) {
            List<Instruction> init = Arrays.asList(
                new ImmutableInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference(Base64.getEncoder().encodeToString(anchor))),
                new ImmutableInstruction11n(Opcode.CONST_4, 1, 0),
                new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 2, 0, 1, 0, 0, 0,
                    new ImmutableMethodReference("Landroid/util/Base64;", "decode", Arrays.asList("Ljava/lang/String;", "I"), "[B")),
                new ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0),
                new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0,
                    new ImmutableMethodReference(target.getDefiningClass(), "addTestRootCertificate", Arrays.asList("[B"), "V")),
                new ImmutableInstruction10x(Opcode.RETURN_VOID));
            Method clinit = new ImmutableMethod(helper, "<clinit>", Collections.emptyList(), "V", 0x10008,
                Collections.emptySet(), Collections.emptySet(), new ImmutableMethodImplementation(2, init, Collections.emptyList(), Collections.emptyList()));
            Method ensure = new ImmutableMethod(helper, "ensure", Collections.emptyList(), "V", 9,
                Collections.emptySet(), Collections.emptySet(), new ImmutableMethodImplementation(0,
                    Arrays.asList(new ImmutableInstruction10x(Opcode.RETURN_VOID)), Collections.emptyList(), Collections.emptyList()));
            helpers.put(helper, new ImmutableClassDef(helper, 0x11, "Ljava/lang/Object;", Collections.emptyList(), null,
                Collections.emptySet(), Collections.emptyList(), Arrays.asList(clinit, ensure)));
        }
        int count = method.getParameterTypes().size();
        List<Instruction> body = Arrays.asList(
            new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference(helper, "ensure", Collections.emptyList(), "V")),
            new ImmutableInstruction3rc(Opcode.INVOKE_STATIC_RANGE, 1, count, ImmutableMethodReference.of(target)),
            new ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0),
            new ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0));
        return new ImmutableMethod(method.getDefiningClass(), method.getName(), method.getParameters(), method.getReturnType(),
            method.getAccessFlags(), method.getAnnotations(), method.getHiddenApiRestrictions(),
            new ImmutableMethodImplementation(count + 1, body, Collections.emptyList(), Collections.emptyList()));
    }
    static boolean apacheHostnameCall(MethodReference ref) {
        if (!Arrays.asList("Lorg/apache/http/conn/ssl/AbstractVerifier;", "Lorg/apache/http/conn/ssl/X509HostnameVerifier;",
                "Lorg/apache/http/conn/ssl/BrowserCompatHostnameVerifier;", "Lorg/apache/http/conn/ssl/StrictHostnameVerifier;",
                "Lorg/apache/http/conn/ssl/DefaultHostnameVerifier;").contains(ref.getDefiningClass())) return false;
        return Arrays.asList("verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z",
                "verify(Ljava/lang/String;Ljava/security/cert/X509Certificate;)V",
                "verify(Ljava/lang/String;Ljavax/net/ssl/SSLSocket;)V",
                "verify(Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;Z)V",
                "verify(Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;)V").contains(methodName(ref));
    }
    static ImmutableMethod hostnameCallsPatched(Method method, Map<String, ClassDef> classes, Map<String, ClassDef> helpers) {
        String helper = "Ldev/repack/tls/ApacheHostname;";
        if (classes.containsKey(helper)) throw new IllegalArgumentException("Hostname helper class collision");
        if (method.getImplementation() == null || method.getName().startsWith("<"))
            throw new IllegalArgumentException("Hostname call-site contract mismatch");
        Map<String, Method> helperMethods = new LinkedHashMap<>();
        if (helpers.containsKey(helper)) for (Method m : helpers.get(helper).getMethods()) helperMethods.put(methodName(m), m);
        List<Instruction> instructions = new ArrayList<>(); int count = 0;
        for (Instruction instruction : method.getImplementation().getInstructions()) {
            MethodReference ref = instruction instanceof ReferenceInstruction && ((ReferenceInstruction)instruction).getReference() instanceof MethodReference
                ? (MethodReference)((ReferenceInstruction)instruction).getReference() : null;
            if (ref == null || !apacheHostnameCall(ref)
                    || !(instruction.getOpcode().name.startsWith("invoke-virtual") || instruction.getOpcode().name.startsWith("invoke-interface"))) {
                instructions.add(ImmutableInstruction.of(instruction)); continue;
            }
            List<String> types = new ArrayList<>(); types.add("Ljava/lang/Object;");
            for (CharSequence parameter : ref.getParameterTypes()) types.add(parameter.toString());
            String name = "verify_" + methodName(ref).replaceAll("[^a-zA-Z0-9]", "_");
            MethodReference replacement = new ImmutableMethodReference(helper, name, types, ref.getReturnType());
            if (!helperMethods.containsKey(methodName(replacement))) {
                List<MethodParameter> parameters = new ArrayList<>();
                for (String type : types) parameters.add(new ImmutableMethodParameter(type, Collections.emptySet(), null));
                List<Instruction> body = new ArrayList<>();
                // getClass preserves a null receiver's NPE; the optional hostname
                // decision is the only behavior deliberately bypassed here.
                body.add(new ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 1, 0, 0, 0, 0,
                    new ImmutableMethodReference("Ljava/lang/Object;", "getClass", Collections.emptyList(), "Ljava/lang/Class;")));
                if (ref.getReturnType().equals("V")) body.add(new ImmutableInstruction10x(Opcode.RETURN_VOID));
                else { body.add(new ImmutableInstruction11n(Opcode.CONST_4, 0, 1)); body.add(new ImmutableInstruction11x(Opcode.RETURN, 0)); }
                helperMethods.put(methodName(replacement), new ImmutableMethod(helper, name, parameters, ref.getReturnType(), 9,
                    Collections.emptySet(), Collections.emptySet(), new ImmutableMethodImplementation(types.size() + 1, body,
                        Collections.emptyList(), Collections.emptyList())));
            }
            if (instruction instanceof FiveRegisterInstruction) {
                FiveRegisterInstruction old = (FiveRegisterInstruction)instruction;
                instructions.add(new ImmutableInstruction35c(Opcode.INVOKE_STATIC, old.getRegisterCount(), old.getRegisterC(), old.getRegisterD(),
                    old.getRegisterE(), old.getRegisterF(), old.getRegisterG(), replacement));
            } else if (instruction instanceof RegisterRangeInstruction) {
                RegisterRangeInstruction old = (RegisterRangeInstruction)instruction;
                instructions.add(new ImmutableInstruction3rc(Opcode.INVOKE_STATIC_RANGE, old.getStartRegister(), old.getRegisterCount(), replacement));
            } else throw new IllegalArgumentException("Unsupported hostname invocation format");
            count++;
        }
        if (count == 0) throw new IllegalArgumentException("No audited Apache hostname call-site");
        helpers.put(helper, new ImmutableClassDef(helper, 0x11, "Ljava/lang/Object;", Collections.emptyList(), null,
            Collections.emptySet(), Collections.emptyList(), helperMethods.values()));
        MethodImplementation old = method.getImplementation();
        return new ImmutableMethod(method.getDefiningClass(), method.getName(), method.getParameters(), method.getReturnType(),
            method.getAccessFlags(), method.getAnnotations(), method.getHiddenApiRestrictions(),
            new ImmutableMethodImplementation(old.getRegisterCount(), instructions, old.getTryBlocks(), old.getDebugItems()));
    }
    static void shadow(File directory, File selection, File output, Opcodes opcodes, byte[] anchor) throws Exception {
        LinkedHashMap<String, Map<String, String>> requested = new LinkedHashMap<>();
        for (String line : Files.readAllLines(selection.toPath(), StandardCharsets.UTF_8)) {
            String[] pair = line.split("\t", -1);
            if (pair.length != 3 || pair[0].isEmpty() || pair[1].isEmpty()
                    || !Arrays.asList("return-void", "return-true", "return-false", "interceptor-proceed", "conscrypt-server-trust", "chromium-anchor", "hostname-callsite", "return-empty-list").contains(pair[2]))
                throw new IllegalArgumentException("Selection requires owner, method and explicit replacement");
            if (requested.computeIfAbsent(pair[0], key -> new LinkedHashMap<>()).putIfAbsent(pair[1], pair[2]) != null)
                throw new IllegalArgumentException("Duplicate requested method");
        }
        if (requested.isEmpty()) throw new IllegalArgumentException("Empty selection");
        DexPool pool = new DexPool(opcodes);
        Set<String> found = new HashSet<>();
        Map<String, ClassDef> classes = new LinkedHashMap<>(), helpers = new LinkedHashMap<>();
        Set<String> duplicate = new HashSet<>();
        for (File dex : dexFiles(directory)) for (ClassDef cls : DexFileFactory.loadDexFile(dex, opcodes).getClasses())
            if (classes.putIfAbsent(cls.getType(), cls) != null) duplicate.add(cls.getType());
        boolean injectHelpers = false;
        for (Map<String, String> methods : requested.values())
            if (methods.containsValue("chromium-anchor") || methods.containsValue("hostname-callsite")) injectHelpers = true;
        if (injectHelpers) for (String type : classes.keySet())
            if (type.startsWith("Ldev/repack/tls/")) throw new IllegalArgumentException("Reserved TLS helper namespace collision");
        for (String name : duplicate) classes.remove(name);
        for (File dex : dexFiles(directory)) for (ClassDef cls : DexFileFactory.loadDexFile(dex, opcodes).getClasses()) {
            if (!requested.containsKey(cls.getType())) continue;
            if (!found.add(cls.getType())) throw new IllegalArgumentException("Ambiguous duplicate class " + cls.getType());
            Map<String, String> remaining = new LinkedHashMap<>(requested.get(cls.getType()));
            List<Method> methods = new ArrayList<>();
            for (Method method : cls.getMethods()) {
                String replacement = remaining.remove(methodName(method));
                if ("chromium-anchor".equals(replacement)) methods.add(chromiumPatched(method, classes, anchor, helpers));
                else if ("hostname-callsite".equals(replacement)) methods.add(hostnameCallsPatched(method, classes, helpers));
                else if (replacement != null) methods.add(patched(method, replacement));
                else methods.add(ImmutableMethod.of(method));
            }
            if (!remaining.isEmpty()) throw new IllegalArgumentException("Missing requested methods " + remaining);
            pool.internClass(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(),
                    cls.getSourceFile(), cls.getAnnotations(), cls.getFields(), methods));
        }
        if (found.size() != requested.size()) throw new IllegalArgumentException("Missing requested class");
        for (ClassDef helper : helpers.values()) pool.internClass(helper);
        FileDataStore store = new FileDataStore(output);
        try { pool.writeTo(store); } finally { store.close(); }
    }
    static void filler(File output, Opcodes opcodes) throws Exception {
        DexPool pool = new DexPool(opcodes);
        int total = 65530;
        for (int start = 0; start < total; start += 512) {
            String type = String.format(Locale.ROOT, "Ldev/repack/fixture/near/Filler%03d;", start / 512);
            List<Method> methods = new ArrayList<>();
            for (int i = start; i < Math.min(start + 512, total); i++) {
                MethodImplementation body = new ImmutableMethodImplementation(0,
                    Collections.singletonList(new ImmutableInstruction10x(Opcode.RETURN_VOID)), Collections.emptyList(), Collections.emptyList());
                methods.add(new ImmutableMethod(type, String.format(Locale.ROOT, "m%03d", i - start), Collections.emptyList(),
                    "V", 9, Collections.emptySet(), Collections.emptySet(), body));
            }
            pool.internClass(new ImmutableClassDef(type, 1, "Ljava/lang/Object;", Collections.emptyList(), null,
                    Collections.emptySet(), Collections.emptyList(), methods));
        }
        FileDataStore store = new FileDataStore(output);
        try { pool.writeTo(store); } finally { store.close(); }
    }
    static void decoy(File output, Opcodes opcodes) throws Exception {
        String type = "Ldev/repack/fixture/decoy/Pretender;";
        MethodImplementation body = new ImmutableMethodImplementation(2, Arrays.asList(
                new ImmutableInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference("Certificate pinning failure!")),
                new ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0)), Collections.emptyList(), Collections.emptyList());
        Method method = new ImmutableMethod(type, "evaluate", Arrays.asList(
                new ImmutableMethodParameter("Ljava/lang/String;", Collections.emptySet(), null),
                new ImmutableMethodParameter("Ljava/util/List;", Collections.emptySet(), null)),
                "Ljava/lang/String;", 9, Collections.emptySet(), Collections.emptySet(), body);
        DexPool pool = new DexPool(opcodes);
        pool.internClass(new ImmutableClassDef(type, 1, "Ljava/lang/Object;", Collections.emptyList(), null,
                Collections.emptySet(), Collections.emptyList(), Collections.singletonList(method)));
        FileDataStore store = new FileDataStore(output);
        try { pool.writeTo(store); } finally { store.close(); }
    }
    public static void main(String[] args) throws Exception {
        String mode = args[0]; Opcodes opcodes = Opcodes.forApi(Integer.parseInt(args[1]));
        if (mode.equals("inspect") && args.length == 3) inspect(new File(args[2]), opcodes);
        else if (mode.equals("shadow") && (args.length == 5 || args.length == 6)) shadow(new File(args[2]), new File(args[3]), new File(args[4]), opcodes,
            args.length == 6 ? Files.readAllBytes(Paths.get(args[5])) : null);
        else if (mode.equals("filler") && args.length == 3) filler(new File(args[2]), opcodes);
        else if (mode.equals("decoy") && args.length == 3) decoy(new File(args[2]), opcodes);
        else throw new IllegalArgumentException("Expected inspect|shadow|filler API paths...");
    }
}
