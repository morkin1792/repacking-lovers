"""Version-one portable artifact manifests; raw execution evidence stays separate."""
import hashlib
import json
from pathlib import Path
import re
import zipfile

from .rebuild import sha256, write_json


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def write_report(report: dict, out: Path) -> None:
    write_json(out, report)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value: raise ValueError('Duplicate JSON key in artifact manifest')
        value[key] = item
    return value


def load_artifact(path: Path) -> tuple[dict, dict]:
    document = json.loads(path.read_text(), object_pairs_hook=unique_object)
    if document.get('schema_version') != 1 or document.get('artifact_type') not in ('apk', 'selected-set'):
        raise ValueError('Unsupported artifact schema/type')
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*', document.get('package', '')):
        raise ValueError('Invalid artifact package')
    if type(document.get('version_code')) is not int or document['version_code'] < 0: raise ValueError('Invalid artifact version')
    if (document.get('transformation') != 'applied' or document.get('host_verification') != 'passed'
            or document.get('verification') != 'not-run' or document.get('runtime_verification') != 'not-run'):
        raise ValueError('Artifact manifests contain build status; runtime verdicts require separate measured reports')
    semantic = document['semantic']
    if semantic['package'] != document['package'] or semantic['version_code'] != document['version_code']:
        raise ValueError('Artifact semantic package/version mismatch')
    if semantic['configuration']['dex_only']: raise ValueError('DEX-only artifacts are not implemented')
    outputs = document['outputs']
    if not isinstance(outputs, list) or not outputs or (document['artifact_type'] == 'apk') != (len(outputs) == 1):
        raise ValueError('Artifact output/member count mismatch')
    members = []; root = path.resolve().parent; seen = set()
    for output in outputs:
        if output['split'] is not None and (not isinstance(output['split'], str) or not output['split']): raise ValueError('Invalid split ID type')
        if output['signer_sha256'] != [semantic['operator_signer_sha256']]: raise ValueError('Artifact member signer declaration differs')
        relative = Path(output['path'])
        apk = (root / relative).resolve()
        if relative.is_absolute() or not apk.is_relative_to(root) or apk in seen:
            raise ValueError('Artifact output path escapes/duplicates its manifest directory')
        seen.add(apk)
        if not re.fullmatch(r'[0-9a-f]{64}', output['sha256']) or sha256(apk) != output['sha256']:
            raise RuntimeError('Artifact output hash mismatch')
        members.append({'apk': str(apk), 'sha256': output['sha256'], 'package': document['package'],
                        'version_code': document['version_code'], 'split': output['split']})
    bases = [item for item in members if not item['split']]
    if len(bases) != 1 or len({item['split'] for item in members}) != len(members): raise ValueError('Artifact base/split IDs are ambiguous')
    with zipfile.ZipFile(bases[0]['apk']) as archive:
        if len(archive.namelist()) != len(set(archive.namelist())): raise ValueError('Duplicate output ZIP entries')
        embedded = json.loads(archive.read('assets/repack/artifact.json'), object_pairs_hook=unique_object)
        if canonical(embedded) != canonical({'schema_version': 1, 'semantic': semantic}): raise RuntimeError('Artifact semantic metadata differs from signed base marker')
    artifact = {'package': document['package'], 'version_code': document['version_code'],
                'signer_sha256': [semantic['operator_signer_sha256']]}
    if len(members) == 1: artifact.update(members[0])
    else: artifact['members'] = members
    return document, artifact


def render_review(document: dict, out: Path) -> None:
    """Render status and evidence references without copying request/response payloads."""
    if out.suffix.lower() != '.md': raise ValueError('Human review output must end in .md')
    runtime = document.get('runtime_verification', 'not-run'); observation = document.get('observations', {})
    lines = ['# Repack verification', '', 'Runtime verification: **' + runtime + '**.', '',
             'Scope: ' + document.get('scope', 'Unspecified') + '.', '']
    semantic = document.get('semantic', {}); action = semantic.get('action', {})
    if action:
        name = action['name'].replace('`', "'").replace('\n', ' ').replace('\r', ' ')
        endpoint = semantic['endpoint']
        lines += ['Action: `' + name + '`.', '', 'HTTPS host: `' + endpoint['host'] + ':' + str(endpoint['port']) + '`.', '',
                  'Matched decrypted requests: ' + str(observation.get('matched_decrypted_requests', 0)) + '.', '',
                  'Reason: `' + document['reason'] + '`.', '']
    lines += ['Artifact manifest: `' + str(document.get('artifact_manifest', '')).replace('`', "'") + '`.', '',
              'The artifact build status and this recorded runtime outcome are separate. Raw payloads remain in the operator-controlled evidence files.', '']
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('x') as output: output.write('\n'.join(lines))
