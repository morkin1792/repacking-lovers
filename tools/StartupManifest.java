import com.reandroid.arsc.chunk.xml.AndroidManifestBlock;
import com.reandroid.arsc.chunk.xml.ResXmlElement;
import com.reandroid.arsc.chunk.xml.ResXmlAttribute;
import java.io.File;
import java.util.Iterator;

/** Inspect or remove exactly QUERY_ALL_PACKAGES; preserve all explicit queries. */
public final class StartupManifest {
    static boolean matches(ResXmlElement e) {
        if (!"uses-permission".equals(e.getName())) return false;
        ResXmlAttribute a = e.searchAttributeByResourceId(0x01010003);
        if (a == null) a = e.searchAttributeByName("name");
        return a != null && "android.permission.QUERY_ALL_PACKAGES".equals(a.getValueString());
    }
    public static void main(String[] args) throws Exception {
        AndroidManifestBlock m = AndroidManifestBlock.load(new File(args[1]));
        ResXmlElement root = m.getManifestElement(); int count = 0;
        Iterator<?> it = root.getElements(); while (it.hasNext()) if (matches((ResXmlElement)it.next())) count++;
        if (args[0].equals("remove")) {
            if (count == 0) throw new IllegalArgumentException("Permission is absent");
            root.removeElementsIf(v -> matches((ResXmlElement)v)); m.refresh(); m.writeBytes(new File(args[2]));
        } else if (!args[0].equals("inspect")) throw new IllegalArgumentException("Unknown operation");
        System.out.println("query_all_packages=" + count);
    }
}
