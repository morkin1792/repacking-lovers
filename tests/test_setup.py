"""Integrity and extraction controls for first-run dependency preparation."""
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from repack.setup import fetch,extract_sdk,operator_key,discover,local_tools_available


class SetupControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
    def test_bad_download_is_not_published(self):
        target=self.root/'tool.jar'
        with patch('repack.setup.urllib.request.urlopen',return_value=io.BytesIO(b'bad')):
            with self.assertRaises(RuntimeError):fetch({'source_url':'https://example.invalid/tool','sha256':'a'*64},target)
        self.assertFalse(target.exists());self.assertFalse(list(self.root.glob('.download-*')))
    def test_verified_cached_dependency_needs_no_network(self):
        target=self.root/'tool.jar';target.write_bytes(b'valid')
        with patch('repack.setup.urllib.request.urlopen') as network:
            fetch({'sha256':hashlib.sha256(b'valid').hexdigest()},target)
        network.assert_not_called()
    def test_sdk_extraction_rejects_traversal_and_symlinks(self):
        for name in ('sdk/../../escaped','/outside/file','sdk/bad\\name'):
            archive=self.root/'input.zip'
            with zipfile.ZipFile(archive,'w') as z:z.writestr(name,b'data')
            with self.assertRaises(ValueError):extract_sdk(archive,self.root/'sdk')
            self.assertFalse((self.root/'sdk').exists())
        with zipfile.ZipFile(archive,'w') as z:
            item=zipfile.ZipInfo('sdk/link');item.external_attr=(0o120777<<16);z.writestr(item,b'/tmp/no')
        with self.assertRaises(ValueError):extract_sdk(archive,self.root/'sdk')
    def test_sdk_layout_and_executable_modes(self):
        archive=self.root/'input.zip'
        with zipfile.ZipFile(archive,'w') as z:
            item=zipfile.ZipInfo('wrapper/bin/tool');item.external_attr=(0o100755<<16);z.writestr(item,b'tool')
            z.writestr('wrapper/lib/data',b'data')
        extract_sdk(archive,self.root/'sdk')
        self.assertEqual((self.root/'sdk/lib/data').read_bytes(),b'data')
        self.assertEqual((self.root/'sdk/bin/tool').stat().st_mode&0o777,0o755)
        with self.assertRaises(Exception):extract_sdk(archive,self.root/'sdk')
    def test_workspace_key_migrates_without_changing_identity(self):
        workspace=self.root/'source';legacy=workspace/'.work/keys/operator';legacy.mkdir(parents=True)
        (legacy/'repack.p12').write_bytes(b'existing-signing-identity');(legacy/'keystore.pass').write_text('existing password')
        key=self.root/'user-data/keys/repack.p12';password=key.parent/'keystore.pass'
        with patch('repack.setup.ROOT',workspace),patch('repack.setup.MANAGED_KEY',key),patch('repack.setup.MANAGED_PASSWORD',password),patch('repack.setup.execute') as execute:
            operator_key({},self.root);self.assertEqual(key.read_bytes(),(legacy/'repack.p12').read_bytes())
            self.assertEqual(password.read_bytes(),(legacy/'keystore.pass').read_bytes())
            (legacy/'repack.p12').write_bytes(b'other-workspace-key')
            operator_key({},self.root);self.assertEqual(key.read_bytes(),b'existing-signing-identity')
        execute.assert_not_called();self.assertEqual(key.stat().st_mode&0o777,0o600)
    def test_missing_existing_operator_key_is_not_regenerated(self):
        key=self.root/'identity/repack.p12';password=key.parent/'keystore.pass';password.parent.mkdir();password.write_text('prior state')
        with patch('repack.setup.ROOT',self.root/'empty'),patch('repack.setup.MANAGED_KEY',key),patch('repack.setup.MANAGED_PASSWORD',password),patch('repack.setup.execute') as execute:
            with self.assertRaisesRegex(Exception,'replacement identity was not generated'):operator_key({},self.root)
        execute.assert_not_called();self.assertFalse(key.exists())

    def test_sdk_environment_and_partial_default_installation(self):
        home=self.root/'home';home.mkdir()
        explicit=self.root/'environment-sdk';(explicit/'platform-tools').mkdir(parents=True)
        default=home/'Android/Sdk';(default/'build-tools').mkdir(parents=True)
        with patch.dict('os.environ',{},clear=True),patch('repack.setup.Path.home',return_value=home),patch('repack.setup.shutil.which',return_value=None):
            found=discover();self.assertEqual(found['sdk'],str(default))
            with patch.dict('os.environ',{'ANDROID_HOME':str(explicit)}):
                found=discover();self.assertEqual(found['sdk'],str(explicit));self.assertEqual(found['sdk_source'],'ANDROID_HOME')
            with patch.dict('os.environ',{'ANDROID_SDK_ROOT':str(explicit)}):
                self.assertEqual(discover()['sdk'],str(explicit))
            preferences=self.root/'preferences';preferences.mkdir()
            with patch.dict('os.environ',{'ANDROID_SDK_HOME':str(preferences)}):
                self.assertEqual(discover()['sdk'],str(default))

    def test_sdk_and_java_can_be_discovered_from_path(self):
        home=self.root/'empty-home';home.mkdir()
        sdk=self.root/'path-sdk';(sdk/'platform-tools').mkdir(parents=True)
        adb=sdk/'platform-tools/adb';adb.touch()
        jdk=self.root/'jdk';(jdk/'bin').mkdir(parents=True);(jdk/'bin/javac').touch()
        with patch.dict('os.environ',{'JAVA_HOME':str(self.root/'missing')},clear=True),patch('repack.setup.Path.home',return_value=home),patch('repack.setup.shutil.which',side_effect=lambda name:str(adb if name=='adb' else jdk/'bin/javac')):
            found=discover();self.assertEqual(found['sdk'],str(sdk));self.assertEqual(found['sdk_source'],'adb on PATH')
            self.assertEqual(found['jdk'],str(jdk))

    def test_automatic_setup_requires_no_sdk_download_when_components_exist(self):
        sdk=self.root/'sdk'
        for part in ('platforms/android-36/android.jar','build-tools/36.0.0/aapt2','build-tools/36.0.0/d8','build-tools/36.0.0/apksigner','build-tools/36.0.0/zipalign','platform-tools/adb'):
            target=sdk/part;target.parent.mkdir(parents=True,exist_ok=True);target.touch()
        info={'supported_host':True,'jdk':'/detected/jdk','sdk':str(sdk)}
        with patch('repack.setup.shutil.which',return_value=None):
            self.assertTrue(local_tools_available(info))
            (sdk/'platforms/android-36/android.jar').unlink();self.assertFalse(local_tools_available(info))

if __name__=='__main__':unittest.main()
