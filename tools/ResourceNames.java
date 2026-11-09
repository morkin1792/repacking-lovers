import com.reandroid.arsc.chunk.TableBlock;
import com.reandroid.arsc.model.ResourceEntry;
import java.io.File;
import java.util.Iterator;

/** Restore only Apktool's synthetic renames, indexed by the original resource ID. */
public final class ResourceNames {
    public static void main(String[] args) throws Exception {
        TableBlock original = TableBlock.load(new File(args[0]));
        TableBlock rebuilt = TableBlock.load(new File(args[1]));
        int restored = 0;
        Iterator<ResourceEntry> resources = original.getResources();
        while (resources.hasNext()) {
            ResourceEntry source = resources.next();
            if (source.getName() == null) continue; // Unallocated slots carry no binding.
            ResourceEntry target = rebuilt.getResource(source.getResourceId());
            if (target == null) throw new IllegalStateException("Missing original resource");
            if (!source.getName().equals(target.getName())) {
                String expected = "APKTOOL_RENAMED_" + String.format("0x%08x", source.getResourceId());
                if (!expected.equals(target.getName())) throw new IllegalStateException("Unexpected resource rename");
                target.setName(source.getName());
                restored++;
            }
        }
        rebuilt.refresh();
        rebuilt.writeBytes(new File(args[2]));
        System.out.println("restored=" + restored);
    }
}
