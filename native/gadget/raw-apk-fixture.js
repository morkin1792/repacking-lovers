'use strict';
rpc.exports = {
  init() {
    if (Process.arch !== 'arm64') throw new Error('Owned ARM64 fixture required');
    const tag = Memory.allocUtf8String('REPACK_GADGET');
    const log = new NativeFunction(Process.getModuleByName('liblog.so').getExportByName('__android_log_write'), 'int', ['int', 'pointer', 'pointer']);
    function emit(item) { item.pid = Process.id; log(4, tag, Memory.allocUtf8String(JSON.stringify(item))); }
    const module = Process.getModuleByName('librepack_gadget_fixture.so');
    const target = module.findExportByName('repack_fixture_raw_gate');
    if (target === null) throw new Error('Owned raw-gate export missing');
    Interceptor.attach(target, {
      onLeave(result) {
        emit({event: 'raw-gate-return', original: result.toInt32(), replacement: 1});
        result.replace(1);
      }
    });
    emit({event: 'attached', module: module.name, target: 'repack_fixture_raw_gate'});
  }
};
