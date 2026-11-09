import unittest
from repack.tls_surfaces import runtime_hints


class RuntimeLeadControls(unittest.TestCase):
    def test_go_and_rust_markers_are_diagnostics_not_patch_implementations(self):
        rows=runtime_hints(b'crypto/tls: failure /rustls-0.23/verify.rs','lib/example.so')
        self.assertEqual({r['runtime'] for r in rows},{'go-tls','rustls'})
        self.assertTrue(all(r['adapter'] is None and r['status'].startswith('research-only') for r in rows))

    def test_foreign_runtime_names_do_not_create_generic_native_targets(self):
        for name,runtime in [('libil2cpp.so','unity-il2cpp'),('libmonosgen-2.0.so','mono')]:
            rows=runtime_hints(b'ordinary',name)
            self.assertEqual(rows[0]['runtime'],runtime);self.assertIsNone(rows[0]['adapter'])

    def test_flutter_and_cronet_have_explicit_scoped_adapter_leads(self):
        for name in ('libflutter.so','libapp.so','libcronet.119.so'):
            rows=runtime_hints(b'',name);self.assertEqual(len(rows),1)
            self.assertTrue(rows[0]['status'].startswith('requires-'))
            self.assertIn('presence-only',rows[0]['interpretation'])


if __name__=='__main__':unittest.main()
