"""Pinned raw-DEX resource rebuild and additive network-security CA anchors."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import re
import ssl
import struct
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

from .rebuild import ROOT, PrerequisiteError, environment, execute, sha256, tool, write_json

APKTOOL_VERSION = '3.0.3'
APKTOOL_SHA256 = 'dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423'
APKTOOL_URL = 'https://github.com/iBotPeaches/Apktool/releases/download/v3.0.3/apktool_3.0.3.jar'
APKTOOL_AAPT2_SHA256 = 'df312db814c018019b2b79a993b041b738d7b76f4a8f28da25bc874a026368cc'
ANDROID = '{http://schemas.android.com/apk/res/android}'
ET.register_namespace('android', ANDROID[1:-1])


def resource_engine(lock: dict, evidence: Path) -> dict:
    jar = ROOT / '.work/tools/apktool-3.0.3.jar'
    if not jar.exists():
        data = urllib.request.urlopen(APKTOOL_URL, timeout=45).read()
        if hashlib.sha256(data).hexdigest() != APKTOOL_SHA256:
            raise RuntimeError('Apktool download differs from pinned release digest')
        jar.parent.mkdir(parents=True, exist_ok=True); jar.write_bytes(data)
    if sha256(jar) != APKTOOL_SHA256:
        raise RuntimeError('Pinned Apktool changed')
    # Decoded private/generated names are accepted by Apktool's patched compiler. The SDK
    # compiler is still used for original source fixtures, badging and independent dumps.
    compiler = ROOT / '.work/tools/apktool-3.0.3-aapt2'
    if not compiler.exists():
        with zipfile.ZipFile(jar) as archive: payload = archive.read('prebuilt/linux/aapt2')
        if hashlib.sha256(payload).hexdigest() != APKTOOL_AAPT2_SHA256: raise RuntimeError('Bundled resource compiler hash differs')
        compiler.write_bytes(payload); compiler.chmod(0o700)
    if sha256(compiler) != APKTOOL_AAPT2_SHA256: raise RuntimeError('Pinned bundled resource compiler changed')
    completed = execute([tool(lock, 'java'), '-jar', str(jar), '--version'], evidence, 'apktool-version',
                        env=environment(lock))
    if completed.stdout.strip() != APKTOOL_VERSION:
        raise RuntimeError('Apktool version mismatch')
    return {'name': 'apktool', 'version': APKTOOL_VERSION, 'path': str(jar), 'sha256': APKTOOL_SHA256,
            'license': 'Apache-2.0', 'source_url': APKTOOL_URL,
            'framework_path': str(ROOT / '.work/tools/apktool-framework'),
            'compiler': {'name': 'apktool-patched-aapt2', 'path': str(compiler), 'sha256': APKTOOL_AAPT2_SHA256,
                         'archive_entry': 'prebuilt/linux/aapt2'}}


def decode_resources(original: Path, decoded: Path, lock: dict, evidence: Path) -> dict:
    engine = resource_engine(lock, evidence)
    if decoded.exists(): raise ValueError('Resource decode requires a fresh directory')
    execute([tool(lock, 'java'), '-jar', engine['path'], 'd', '-s', '-j', '2',
             '--frame-path', engine['framework_path'], '--output', str(decoded), str(original)],
             evidence, 'resource-decode', env=environment(lock))
    with zipfile.ZipFile(original) as archive:
        has_table = 'resources.arsc' in archive.namelist()
        table = archive.read('resources.arsc') if has_table else None
        empty_table = (table is not None and len(table) >= 12 and struct.unpack_from('<HHII', table) == (2, 12, len(table), 0))
        no_table = not has_table or empty_table
    if no_table:
        # Apktool records an empty package/id0 when the input had no resource table.
        # Introducing the first CA/XML needs a normal application resource package.
        package = ET.parse(decoded / 'AndroidManifest.xml').getroot().get('package')
        if not package or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*', package):
            raise RuntimeError('Resource-less APK has no valid manifest package')
        metadata = decoded / 'apktool.yml'; text = metadata.read_text()
        text, count = re.subn(r'(?m)^resourcesInfo:\n  packageId: 0\n  packageName:[ \t]*$',
            'resourcesInfo:\n  packageId: 127\n  packageName: ' + package, text)
        if count != 1: raise RuntimeError('Unexpected pinned Apktool metadata for resource-less input')
        metadata.write_text(text)
        write_json(evidence / 'resource-less-bootstrap.json', {'input_has_resource_table': has_table, 'existing_resource_package_count': 0,
            'new_resource_package': package, 'new_resource_package_id': 127})
    return engine


def rebuild_resources(original: Path, decoded: Path, out: Path, lock: dict, evidence: Path) -> dict:
    engine = resource_engine(lock, evidence)
    if out.exists(): raise ValueError('Resource output already exists')
    raw = out.with_name(out.stem + '-apktool.apk')
    execute([tool(lock, 'java'), '-jar', engine['path'], 'b', '-j', '2', '--aapt', engine['compiler']['path'],
             '--frame-path', engine['framework_path'], '--output', str(raw), str(decoded)],
             evidence, 'resource-build', env=environment(lock))
    preserved = []
    with zipfile.ZipFile(original) as source, zipfile.ZipFile(raw) as built, zipfile.ZipFile(out, 'w') as target:
        originals = {item.filename: item for item in source.infolist()}
        rebuilt = {item.filename: item for item in built.infolist()}
        if len(originals) != len(source.infolist()) or len(rebuilt) != len(built.infolist()):
            raise RuntimeError('Duplicate ZIP entries in resource input/output')
        # DEX, native libraries, assets and other opaque payloads bypass resource decoding.
        def signature(name):
            return name == 'stamp-cert-sha256' or (name.startswith('META-INF/') and name.upper().endswith(('.SF', '.RSA', '.DSA', '.EC', 'MANIFEST.MF')))
        opaque = {name for name in originals if name != 'AndroidManifest.xml' and name != 'resources.arsc'
                  and not name.startswith('res/') and not signature(name) and not name.endswith('/')}
        for name in sorted(set(rebuilt) | opaque):
            if name.endswith('/') or signature(name): continue
            if name in opaque:
                data = source.read(name); item = copy.copy(originals[name])
                if re.fullmatch(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex', name) and (
                        name not in rebuilt or built.read(name) != data):
                    raise RuntimeError('Raw DEX changed during resource rebuild: ' + name)
                preserved.append({'entry': name, 'sha256': hashlib.sha256(data).hexdigest(),
                                  'compression': item.compress_type})
            else:
                data = built.read(name); item = copy.copy(rebuilt[name])
                if name == 'resources.arsc': item.compress_type = zipfile.ZIP_STORED
                elif name in originals and source.read(name) == data:
                    item.compress_type = originals[name].compress_type
            target.writestr(item, data)
    original_ids = resource_ids(original, lock, evidence, 'original-resource-ids')
    rebuilt_ids = resource_ids(out, lock, evidence, 'rebuilt-resource-ids')
    changed = {key: (value, rebuilt_ids.get(key)) for key, value in original_ids.items() if rebuilt_ids.get(key) != value}
    restored = 0
    if changed and all(new == old.split('/', 1)[0] + '/APKTOOL_RENAMED_' + key
                       for key, (old, new) in changed.items()):
        # AAPT source names cannot represent some obfuscated names (e.g. decimal IDs).
        # Restore those names in the compiled binary table, retaining numeric IDs.
        restore_resource_names(original, out, lock, evidence)
        rebuilt_ids = resource_ids(out, lock, evidence, 'restored-resource-ids')
        restored = len(changed)
        changed = {key: (value, rebuilt_ids.get(key)) for key, value in original_ids.items() if rebuilt_ids.get(key) != value}
    if changed: raise RuntimeError('Resource rebuild changed original ID/name bindings')
    return {'unsigned_apk': str(out), 'sha256': sha256(out), 'engine': engine, 'preserved_entries': preserved,
            'resource_ids': {'original_count': len(original_ids), 'output_count': len(rebuilt_ids), 'original_bindings_preserved': True,
                             'synthetic_names_restored': restored}}


def restore_resource_names(original: Path, rebuilt: Path, lock: dict, evidence: Path) -> None:
    from .shim import manifest_editor
    from .rebuild import copy_archive
    jar, _ = manifest_editor(lock, evidence)
    classes = evidence / 'resource-name-classes'; classes.mkdir()
    execute([tool(lock, 'javac'), '--release', '8', '-classpath', str(jar), '-d', str(classes),
             str(ROOT / 'tools/ResourceNames.java')], evidence, 'resource-names-compile', env=environment(lock))
    tables = []
    for label, apk in [('original', original), ('rebuilt', rebuilt)]:
        table = evidence / (label + '-names.arsc')
        with zipfile.ZipFile(apk) as archive: table.write_bytes(archive.read('resources.arsc'))
        tables.append(str(table))
    restored = evidence / 'restored-names.arsc'
    execute([tool(lock, 'java'), '-classpath', str(classes) + ':' + str(jar), 'ResourceNames', *tables, str(restored)],
            evidence, 'resource-names-restore', env=environment(lock))
    replacement = evidence / 'names-restored.apk'
    copy_archive(rebuilt, replacement, replacements={'resources.arsc': restored.read_bytes()})
    replacement.replace(rebuilt)


def resource_ids(apk: Path, lock: dict, evidence: Path, label: str) -> dict:
    output = execute([tool(lock, 'aapt2'), 'dump', 'resources', str(apk)], evidence, label).stdout
    pairs = re.findall(r'^\s*resource (0x[0-9a-fA-F]+) (\S+)', output, re.M)
    result = dict(pairs)
    if len(result) != len(pairs): raise RuntimeError('Duplicate resource IDs in independent SDK dump')
    return result


def public_ca(ca: Path) -> tuple[str, bytes]:
    from .certificates import decode_public, MAX_CERTIFICATE
    with ca.open('rb') as stream:
        certificate = decode_public(stream.read(MAX_CERTIFICATE + 1))
    return certificate['sha256'], certificate['der']


def add_trust_anchor(decoded: Path, ca: Path, target_sdk: int) -> dict:
    fingerprint, der = public_ca(ca)
    manifest_path = decoded / 'AndroidManifest.xml'
    manifest = ET.parse(manifest_path)
    application = manifest.getroot().find('application')
    if application is None: raise RuntimeError('Missing application element')
    reference = application.get(ANDROID + 'networkSecurityConfig')
    existing = bool(reference)
    if reference:
        match = re.fullmatch(r'@xml/([a-zA-Z0-9_]+)', reference)
        if not match: raise PrerequisiteError('Unresolved/aliased NSC reference: ' + reference)
        configs = sorted(decoded.glob('res/xml*/' + match[1] + '.xml'))
        if not configs: raise RuntimeError('Referenced NSC resource missing after decode')
    else:
        name = 'repack_network_security_config'
        while list(decoded.glob('res/xml*/' + name + '.xml')): name += '_'
        path = decoded / 'res/xml' / (name + '.xml'); path.parent.mkdir(parents=True, exist_ok=True)
        root = ET.Element('network-security-config')
        base = ET.SubElement(root, 'base-config')
        cleartext = application.get(ANDROID + 'usesCleartextTraffic')
        if cleartext is not None: base.set('cleartextTrafficPermitted', cleartext)
        ET.ElementTree(root).write(path, encoding='utf-8', xml_declaration=True)
        application.set(ANDROID + 'networkSecurityConfig', '@xml/' + name)
        configs = [path]
    raw = decoded / 'res/raw'; raw.mkdir(parents=True, exist_ok=True)
    name = 'repack_ca'
    # A raw resource can have any extension/qualifier; do not collide with existing names.
    while any(p.stem == name for directory in decoded.glob('res/raw*') for p in directory.iterdir()): name += '_'
    (raw / (name + '.der')).write_bytes(der)
    policies = []
    for path in configs:
        tree = ET.parse(path); root = tree.getroot()
        if root.tag != 'network-security-config': raise RuntimeError('NSC root element mismatch')
        before = ET.tostring(root, encoding='unicode')
        base = root.find('base-config')
        if base is None: base = ET.SubElement(root, 'base-config')
        anchors = base.find('trust-anchors')
        if anchors is None:
            anchors = ET.SubElement(base, 'trust-anchors')
            ET.SubElement(anchors, 'certificates', {'src': 'system'})
            if target_sdk <= 23: ET.SubElement(anchors, 'certificates', {'src': 'user'})
        sets = list(root.iter('trust-anchors'))
        for anchor_set in sets:
            ET.SubElement(anchor_set, 'certificates', {'src': '@raw/' + name, 'overridePins': 'true'})
        tree.write(path, encoding='utf-8', xml_declaration=True)
        policies.append({'file': str(path.relative_to(decoded)), 'original_xml': before,
                         'modified_xml': ET.tostring(root, encoding='unicode'), 'anchor_sets': len(sets)})
    manifest.write(manifest_path, encoding='utf-8', xml_declaration=True)
    return {'ca_sha256': fingerprint, 'ca_resource': '@raw/' + name,
            'existing_nsc': existing, 'nsc_reference': application.get(ANDROID + 'networkSecurityConfig'),
            'policies': policies}


def apply_trust(original: Path, ca: Path, out: Path, lock: dict) -> dict:
    public_ca(ca)  # reject private material before decode/output
    out.mkdir(parents=True, exist_ok=False)
    decoded = out / 'decoded'
    decode_resources(original, decoded, lock, out)
    # Resolve actual targetSdk from the selected SDK's independent APK reader.
    text = execute([tool(lock, 'aapt2'), 'dump', 'badging', str(original)], out, 'trust-input-badging').stdout
    target = re.search(r"targetSdkVersion:'(\d+)'", text)
    if target is None: raise PrerequisiteError('Missing targetSdk for trust defaults')
    policy = add_trust_anchor(decoded, ca, int(target[1]))
    result = rebuild_resources(original, decoded, out / 'unsigned.apk', lock, out)
    result.update(input=str(original), input_sha256=sha256(original), **policy)
    write_json(out / 'trust.json', result)
    return result
