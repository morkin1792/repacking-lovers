"""Public patch composition over the accepted manifest, trust and Java transforms."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl

from .rebuild import (ROOT, PrerequisiteError, align_sign, copy_archive, environment, execute, sha256,
                      source_hash, tool, write_json)
from .recon import inspect_input, triage
from .report import canonical, write_report
from .shim import build_bootstrap, parse_proxy
from .trust import apply_trust, public_ca
from .patches import UnsupportedJavaPatch, patch_apk
from . import integrity as native_integrity
from . import native_tls
from . import dart_pinning
from . import gadget as gadget_module


class UnsupportedOperation(ValueError):
    pass


def validate_toolchain(lock: dict, *, device=False) -> dict:
    names = ['java', 'javac', 'keytool', 'd8', 'aapt2', 'apksigner', 'zipalign'] + (['adb'] if device else [])
    result = {}
    for name in names:
        pin = lock['tools'][name]; path = Path(pin['path'])
        if not path.is_file() or sha256(path) != pin['sha256']: raise PrerequisiteError('Locked tool changed/missing: ' + name)
        result[name] = {'sha256': pin['sha256']}
        if 'jar_sha256' in pin:
            jar = path.parent / 'lib' / (name + '.jar')
            if sha256(jar) != pin['jar_sha256']: raise PrerequisiteError('Locked tool JAR changed: ' + name)
            result[name]['jar_sha256'] = pin['jar_sha256']
    result['android_jar'] = {'sha256': sha256(Path(lock['android_jar']))}
    if result['android_jar']['sha256'] != lock.get('android_jar_sha256'):
        raise PrerequisiteError('Locked public android.jar changed/missing hash')
    return result


def resolve_key(path: Path, lock: dict, evidence: Path) -> dict:
    if not path.is_file(): raise PrerequisiteError('Signing key does not exist; no replacement key was generated')
    fixture = path.resolve() == (ROOT / '.work/keys/repack.p12').resolve()
    password = os.environ.get('REPACK_KEYSTORE_PASSWORD_FILE') or (str(ROOT / '.work/keys/fixture.pass') if fixture else None)
    alias = os.environ.get('REPACK_KEY_ALIAS') or ('repack' if fixture else None)
    if not password or not alias or not Path(password).is_file():
        raise PrerequisiteError('Set REPACK_KEYSTORE_PASSWORD_FILE and REPACK_KEY_ALIAS for the existing operator key')
    certificate = evidence / 'operator-certificate.der'
    execute([tool(lock, 'keytool'), '-exportcert', '-alias', alias, '-keystore', str(path), '-storepass:file', password,
             '-file', str(certificate)], evidence, 'operator-cert-export', env=environment(lock))
    result = {'path': str(path.resolve()), 'alias': alias, 'password_file': str(Path(password).resolve()), 'sha256': sha256(certificate)}
    separate = os.environ.get('REPACK_KEY_PASSWORD_FILE')
    if separate:
        if not Path(separate).is_file(): raise PrerequisiteError('Separate key password file is missing')
        if Path(separate).resolve() != Path(password).resolve(): result['key_password_file'] = str(Path(separate).resolve())
    return result


def patch(input_ref: str, options: dict, lock: dict, evidence: Path) -> dict:
    revision = source_hash()
    if options.get('trust_only') and options.get('dex_only'): raise ValueError('--trust-only and --dex-only conflict')
    if options.get('trust_only') and (options.get('proxy') is not None or options.get('antitamper') or options.get('integrity') or options.get('native_tls') or options.get('gadget') or options.get('relax_hostname') or options.get('dart_pinning')):
        raise ValueError('--trust-only changes trust alone; routing, identity, native/Gadget, Dart and hostname patches are incompatible')
    if options.get('dex_only'): raise UnsupportedOperation('DEX-only bootstrap/runtime trust is not implemented; no artifact was produced')
    tools = validate_toolchain(lock, device=bool(options.get('device')))
    if options.get('trust_only'):
        source = inspect_input(input_ref, options.get('device'), lock, evidence / 'p0', device_spec=options.get('device_spec'))
        source['triage'] = {'code_verification': 'not-run', 'helper_class_collisions': [], 'cross_member_duplicate_classes': {}}
    else: source = triage(input_ref, options.get('device'), lock, evidence / 'p0', device_spec=options.get('device_spec'))
    out = Path(options['out']).resolve(); single = len(source['members']) == 1
    if single and out.suffix.lower() != '.apk': raise ValueError('Single APK --out must end in .apk')
    if not single and out.suffix.lower() == '.apk': raise ValueError('Selected set --out must be a directory')
    manifest_path = out.with_suffix('.artifact.json') if single else out / 'manifest.json'
    if out.exists() or out.is_symlink() or manifest_path.exists(): raise ValueError('Output/manifest already exists; choose a fresh path')
    native_plan = None
    if options.get('integrity'):
        try: native_plan = native_integrity.plan(source, options['integrity'], options.get('device'), evidence / 'native-plan')
        except native_integrity.IntegrityUnsupported as error: raise UnsupportedOperation(str(error)) from error
    tls_bytes = tls_plan = None
    if options.get('native_tls'):
        try: tls_bytes, tls_plan = native_tls.plan(source, options['native_tls'])
        except native_tls.NativeTlsUnsupported as error: raise UnsupportedOperation(str(error)) from error
    dart_bytes = dart_plan = None
    if options.get('dart_pinning'):
        try: dart_bytes, dart_plan = dart_pinning.plan(source, evidence / 'dart-plan')
        except dart_pinning.DartPinningUnsupported as error: raise UnsupportedOperation(str(error)) from error
        if tls_plan is not None and tls_plan['mode'] == 'offline-arm64' and (dart_plan['member'], dart_plan['entry']) in tls_bytes:
            raise UnsupportedOperation('Native and Dart plans overlap the same library; no edit was discarded')
    gadget_assets = gadget_plan = None
    if options.get('gadget'):
        try: gadget_assets, gadget_plan = gadget_module.plan(source, options['gadget'])
        except gadget_module.GadgetUnsupported as error: raise UnsupportedOperation(str(error)) from error
    key = resolve_key(Path(options['key']), lock, evidence)
    ca = Path(options.get('ca') or Path.home() / '.mitmproxy/mitmproxy-ca-cert.pem')
    if not ca.is_file(): raise PrerequisiteError('Provide --ca with the public PEM matching the configured proxy')
    ca_sha, ca_der = public_ca(ca)
    ca = evidence / 'public-ca.pem'; ca.write_text(ssl.DER_cert_to_PEM_cert(ca_der))
    proxy = None if options.get('trust_only') else options.get('proxy') or parse_proxy('127.0.0.1:8080')
    if proxy is not None:
        proxy = parse_proxy(('[' + proxy['host'] + ']' if ':' in proxy['host'] else proxy['host']) + ':' + str(proxy['port']))
    antitamper = bool(options.get('antitamper'))
    if antitamper and source['metadata_api'] != 30: raise UnsupportedOperation('Identity adapter is accepted only for API30')
    conflicts = source['triage']['helper_class_collisions']
    if not options.get('trust_only') and any(item['class'].startswith('Ldev/repack/shim/') or antitamper for item in conflicts):
        raise UnsupportedOperation('Original DEX conflicts with a required helper/dependency class; no unsafe shadow was selected')
    configuration = {'antitamper_requested': antitamper, 'antitamper_selected': antitamper,
                     'antitamper_reason': 'explicit-request/accepted-api30' if antitamper else 'explicit-opt-in-not-requested',
                     'trust_only': bool(options.get('trust_only')), 'dex_only': False, 'proxy': proxy, 'ca_sha256': ca_sha}
    if options.get('relax_hostname'): configuration['relax_hostname'] = True
    if dart_plan is not None: configuration['dart_pinning'] = dart_plan
    if native_plan is not None: configuration['integrity'] = native_plan
    if tls_plan is not None: configuration['native_tls'] = tls_plan
    if gadget_plan is not None: configuration['gadget'] = gadget_plan
    inputs = [{'split': item.get('split'), 'sha256': item['sha256'], 'signer_sha256': item['signing']['signer_sha256']} for item in source['members']]
    build_id = hashlib.sha256(canonical({'inputs': inputs, 'configuration': configuration, 'key': key['sha256'],
                                         'source': revision, 'tools': tools})).hexdigest()
    base = next(item for item in source['members'] if not item.get('split')); signing = base['signing']
    staging = evidence / 'staging'; staging.mkdir(); pending = []; transforms = []
    native_additions = {}; native_notices = {}; native_build = None
    if native_plan is not None:
        native_additions, native_notices, native_build = native_integrity.build(native_plan, evidence / 'native-build')
    for index, member in enumerate(source['members']):
        part = staging / str(index); part.mkdir(); current = Path(member['apk']); is_base = not member.get('split')
        if is_base:
            trust = apply_trust(current, ca, part / 'trust', lock); current = Path(trust['unsigned_apk'])
            transforms.append({'component': 'trust', 'member': 'base', 'transformation': 'applied', 'ca_sha256': ca_sha,
                               'engine': trust['engine']['sha256'], 'compiler_sha256': trust['engine']['compiler']['sha256'],
                               'resource_ids': trust['resource_ids']})
        if not options.get('trust_only') and member['dex']:
            duplicates = source['triage']['cross_member_duplicate_classes']
            if duplicates:
                transforms.append({'component': 'java', 'member': member.get('split') or 'base', 'transformation': 'unsupported', 'reason': 'cross-member-class-ambiguity'})
            else:
                java_evidence = part / 'java-evidence'; java_evidence.mkdir()
                try:
                    changed = patch_apk(current, part / 'java', key, lock, java_evidence, chromium_ca=ca_der, relax_hostname=bool(options.get('relax_hostname'))); current = Path(changed['apk'])
                    transforms.append({'component': 'java', 'member': member.get('split') or 'base', 'transformation': 'applied',
                                       'methods': [{'class': row['class'], 'method': row['method'], 'kind': row['kind'],
                                                    'replacement': row['replacement']} for row in changed['patches']]})
                except UnsupportedJavaPatch:
                    candidates = json.loads((part / 'java/candidates.json').read_text())
                    transforms.append({'component': 'java', 'member': member.get('split') or 'base',
                                       'transformation': 'unsupported' if candidates['rejected'] else 'skipped', 'reason': 'no-accepted-java-candidates'})
        if is_base and not options.get('trust_only'):
            bootstrap_evidence = part / 'bootstrap-evidence'; bootstrap_evidence.mkdir()
            bootstrap = build_bootstrap(current, part / 'bootstrap', key, lock, bootstrap_evidence, proxy=proxy,
                identity_mode='identity' if antitamper else 'none', probe_token=build_id,
                original_certificates=[Path(item['der']).read_bytes() for item in signing['certificates']] if antitamper else None,
                historical_certificates=[Path(item['der']).read_bytes() for item in signing['history']] if antitamper else None,
                original_scheme=signing['scheme_version'] if antitamper else 0, signing_contracts=antitamper,
                package_binder=antitamper, identity_input_sha256=base['sha256'], integrity=native_plan,
                retained_original=Path(base['apk']).read_bytes() if native_plan is not None else None, gadget=gadget_plan)
            current = Path(bootstrap['apk'])
            transforms.append({'component': 'routing', 'member': 'base', 'transformation': 'applied', 'proxy': proxy})
            transforms.append({'component': 'identity', 'member': 'base', 'transformation': 'applied' if antitamper else 'skipped',
                               'api': source['metadata_api'] if antitamper else None})
        if native_plan is not None:
            additions = dict(native_notices) if is_base else {}
            if (member.get('split') or 'base') == native_plan['member']:
                additions.update(native_additions)
                transforms.append({'component': 'integrity', 'member': native_plan['member'], 'transformation': 'applied',
                    'mode': native_plan['mode'], 'callers': native_plan['callers'], 'abi': native_plan['abi'],
                    'retained_input_base_sha256': base['sha256'], 'libraries': native_build['libraries'],
                    'limitations': native_plan['limitations'], 'runtime_verification': 'not-run'})
            if additions:
                modified = part / 'native-unsigned.apk'; copy_archive(current, modified, additions=additions); current = modified
        if tls_plan is not None:
            tls_additions = {}; tls_replacements = {}
            if tls_plan['mode'] == 'offline-arm64':
                member_id = member.get('split') or 'base'
                for library in tls_plan['libraries']:
                    if library['member'] == member_id:
                        tls_replacements[library['entry']] = tls_bytes[(member_id, library['entry'])]
                        transforms.append({'component': 'native-tls', 'transformation': 'applied', **library})
            elif (member.get('split') or 'base') == tls_plan['member']:
                tls_replacements[tls_plan['entry']] = tls_bytes
                transforms.append({'component': 'native-tls', 'transformation': 'applied', **tls_plan})
            if is_base and tls_plan['mode'] != 'offline-arm64':
                pin = native_tls.dependencies()
                tls_additions['assets/repack/reflutter/LICENSE.txt'] = (ROOT / pin['upstream_license']['path']).read_bytes()
                tls_additions['assets/repack/reflutter/source.json'] = canonical({'upstream': pin['upstream_commit'], 'replacement': pin['replacement']['url']})
            if tls_additions or tls_replacements:
                tls_unsigned = part / 'native-tls-unsigned.apk'
                copy_archive(current, tls_unsigned, replacements=tls_replacements, additions=tls_additions); current = tls_unsigned
        if gadget_plan is not None and is_base:
            gadget_unsigned = part / 'gadget-unsigned.apk'
            copy_archive(current, gadget_unsigned, additions=gadget_assets); current = gadget_unsigned
            transforms.append({'component': 'gadget', 'transformation': 'applied', 'member': 'base', **gadget_plan})
        if dart_plan is not None and (member.get('split') or 'base') == dart_plan['member']:
            unsigned = part / 'dart-pinning-unsigned.apk'
            copy_archive(current, unsigned, replacements={dart_plan['entry']: dart_bytes}); current = unsigned
            transforms.append({'component': 'dart-pinning', 'transformation': 'applied', **dart_plan})
        pending.append((member, current, part))
    semantic = {'artifact_build_id': build_id, 'package': source['package'], 'version_code': source['version_code'],
                'input_members': inputs, 'configuration': configuration, 'operator_signer_sha256': key['sha256'],
                'original_identity': {'metadata_api': source['metadata_api'], 'input_base_sha256': base['sha256'],
                    'signer_sha256': signing['signer_sha256'], 'history_sha256': [item['sha256'] for item in signing['history']],
                    'scheme_version': signing['scheme_version']},
                'provenance': source['provenance'], 'transforms': transforms, 'source_sha256': revision, 'tools': tools,
                'runtime_scope': 'not-run; acceptance is limited to the recorded fixture cells'}
    if source.get('container'):
        container = source['container']
        semantic['input_container'] = {'kind': container['kind'], 'sha256': container['sha256'],
            'selection': container['selection'], 'device_spec': container['device_spec'],
            'selected': [{k: row[k] for k in ('path', 'sha256', 'size')} for row in container['selected']],
            'bundletool_sha256': (container.get('bundletool') or {}).get('sha256')}
    staged = []
    for member, current, part in pending:
        import re
        split = member.get('split')
        if split and not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', split): raise UnsupportedOperation('Split ID cannot form a safe portable filename')
        name = out.name if single else 'split_' + split + '.apk' if split else 'base.apk'
        unsigned = part / 'final-unsigned.apk'; signed = part / 'final.apk'
        additions = {} if split else {'assets/repack/artifact.json': canonical({'schema_version': 1, 'semantic': semantic})}
        copy_archive(current, unsigned, additions=additions)
        sign_evidence = part / 'final-sign-evidence'; sign_evidence.mkdir(); align_sign(unsigned, signed, key, lock, sign_evidence)
        staged.append({'path': name, 'split': split, 'sha256': sha256(signed), 'signer_sha256': [key['sha256']], 'staged': signed})
    if any(sha256(Path(item['apk'])) != item['sha256'] for item in source['members']): raise PrerequisiteError('Original input changed during patching')
    if source.get('container'):
        from .containers import validate_snapshot
        validate_snapshot(source['container'])
    if source_hash() != revision: raise PrerequisiteError('Implementation changed during patching; staged output was not published')
    if validate_toolchain(lock, device=bool(options.get('device'))) != tools: raise PrerequisiteError('Toolchain changed during patching')
    if native_plan is not None:
        native_integrity.dependencies()
        if (sha256(ROOT / 'config/bytehook-dependency.json') != native_plan['dependency_pin_sha256']
                or sha256(ROOT / 'config/ndk-dependency.json') != native_plan['ndk_pin_sha256']):
            raise PrerequisiteError('Native dependency/build lock changed during patching')
    if tls_plan is not None and tls_plan['mode'] != 'offline-arm64':
        native_tls.dependencies()
        if sha256(ROOT / 'config/flutter-dependency.json') != tls_plan['dependency_pin_sha256']:
            raise PrerequisiteError('Native TLS dependency lock changed during patching')
    if dart_plan is not None:
        if (sha256(ROOT / 'config/dart-analysis-dependency.json') != dart_plan['dependency_pin_sha256']
                or sha256(ROOT / dart_plan['analyzer_path']) != dart_plan['analyzer_sha256']):
            raise PrerequisiteError('Dart analyzer or dependency lock changed during patching')
    if gadget_plan is not None:
        gadget_module.dependencies()
        if sha256(ROOT / 'config/gadget-dependency.json') != gadget_plan['dependency_pin_sha256']:
            raise PrerequisiteError('Gadget dependency lock changed during patching')
    destination = out.parent if single else out
    if single: destination.mkdir(parents=True, exist_ok=True)
    else: destination.mkdir(parents=True, exist_ok=False)
    outputs = []
    for item in staged:
        with (destination / item['path']).open('xb') as target, item['staged'].open('rb') as original: shutil.copyfileobj(original, target)
        outputs.append({key_: value for key_, value in item.items() if key_ != 'staged'})
    document = {'schema_version': 1, 'artifact_type': 'apk' if single else 'selected-set', 'package': source['package'],
                'version_code': source['version_code'], 'semantic': semantic, 'outputs': outputs,
                'transformation': 'applied', 'host_verification': 'passed', 'verification': 'not-run', 'runtime_verification': 'not-run'}
    write_report(document, manifest_path)
    return {'manifest': str(manifest_path), 'artifact': document, 'inventory': source}
