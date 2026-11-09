import com.reandroid.arsc.chunk.xml.AndroidManifestBlock;
import com.reandroid.arsc.chunk.xml.ResXmlAttribute;
import com.reandroid.arsc.chunk.xml.ResXmlElement;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Iterator;
import com.reandroid.json.JSONObject;
import com.reandroid.json.JSONArray;

/** Binary manifest edits only; all ZIP copying remains in the Python build path. */
public final class ManifestEdit {
    private static void value(String name, String value) {
        System.out.println(name + "=" + Base64.getEncoder().encodeToString(
                (value == null ? "" : value).getBytes(StandardCharsets.UTF_8)));
    }
    private static Object attribute(ResXmlElement element, String name) {
        ResXmlAttribute item = element.searchAttributeByName(name);
        return item == null ? JSONObject.NULL : item.getValueAsEncoded();
    }

    public static void main(String[] args) throws Exception {
        AndroidManifestBlock manifest = AndroidManifestBlock.load(new File(args[1]));
        ResXmlElement application = manifest.getApplicationElement();
        if (application == null) throw new IllegalArgumentException("Missing application element");
        ResXmlAttribute factory = application.searchAttributeByResourceId(android.R.attr.appComponentFactory);
        value("package", manifest.getPackageName());
        value("factory", factory == null ? null : factory.getValueString());
        if (args[0].equals("inventory")) {
            ResXmlElement root = manifest.getManifestElement();
            JSONObject info = new JSONObject();
            info.put("package", manifest.getPackageName()); info.put("split", manifest.getSplit() == null ? JSONObject.NULL : manifest.getSplit());
            info.put("version_code", manifest.getVersionCode()); info.put("version_code_major", attribute(root, "versionCodeMajor"));
            info.put("version_name", manifest.getVersionName()); info.put("min_sdk", manifest.getMinSdkVersion());
            info.put("target_sdk", manifest.getTargetSdkVersion()); info.put("extract_native_libs", manifest.isExtractNativeLibs());
            info.put("factory", factory == null ? JSONObject.NULL : factory.getValueString());
            info.put("application", manifest.getApplicationClassName());
            for (String name : new String[] {"configForSplit", "isFeatureSplit", "requiredSplitTypes", "splitTypes"}) info.put(name, attribute(root, name));
            info.put("isSplitRequired", attribute(application, "isSplitRequired"));
            JSONArray dependencies = new JSONArray(); Iterator<?> children = root.getElements("uses-split");
            while (children.hasNext()) dependencies.put(attribute((ResXmlElement) children.next(), "name"));
            info.put("uses_split", dependencies); value("metadata", info.toString());
        } else if (args[0].equals("fixture-extract-false")) {
            if (!"dev.repack.fixture.identity".equals(manifest.getPackageName())) throw new IllegalArgumentException("Owned fixture required");
            application.getOrCreateAndroidAttribute("extractNativeLibs", android.R.attr.extractNativeLibs).setValueAsBoolean(false);
            manifest.refresh(); manifest.writeBytes(new File(args[2]));
        } else if (args[0].equals("fixture-test-only")) {
            if (!"dev.repack.fixture.identity".equals(manifest.getPackageName())) throw new IllegalArgumentException("Owned fixture required");
            application.getOrCreateAndroidAttribute("testOnly", android.R.attr.testOnly).setValueAsBoolean(true);
            manifest.refresh(); manifest.writeBytes(new File(args[2]));
        } else if (args[0].equals("split-types")) {
            manifest.getManifestElement().getOrCreateAndroidAttribute("splitTypes", android.R.attr.splitTypes).setValueAsString(args[3]);
            manifest.refresh(); manifest.writeBytes(new File(args[2]));
        } else if (args[0].equals("factory")) {
            application.getOrCreateAndroidAttribute("appComponentFactory", android.R.attr.appComponentFactory)
                    .setValueAsString(args[3]);
            manifest.refresh();
            manifest.writeBytes(new File(args[2]));
        } else if (args[0].equals("clear-factory")) {
            application.removeAttributesWithId(android.R.attr.appComponentFactory);
            manifest.refresh();
            manifest.writeBytes(new File(args[2]));
        } else if (!args[0].equals("inspect")) {
            throw new IllegalArgumentException("Unknown manifest operation");
        }
    }
}
