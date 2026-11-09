import java.io.*;
import java.util.jar.*;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;

/** dex2jar does not emit Java stack-map frames. Recompute them for strict JVM
 * verification against the original fixture classpath; never disable verification.
 */
public final class FixtureFrames {
    public static void main(String[] args) throws Exception {
        try (JarInputStream input = new JarInputStream(new FileInputStream(args[0]));
             JarOutputStream output = new JarOutputStream(new FileOutputStream(args[1]))) {
            JarEntry item;
            while ((item = input.getNextJarEntry()) != null) {
                ByteArrayOutputStream bytes = new ByteArrayOutputStream(); byte[] buffer = new byte[8192]; int read;
                while ((read = input.read(buffer)) != -1) bytes.write(buffer, 0, read);
                byte[] data = bytes.toByteArray();
                if (item.getName().endsWith(".class")) {
                    ClassReader reader = new ClassReader(data);
                    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
                    reader.accept(writer, ClassReader.SKIP_FRAMES); data = writer.toByteArray();
                }
                output.putNextEntry(new JarEntry(item.getName())); output.write(data); output.closeEntry();
            }
        }
    }
}
