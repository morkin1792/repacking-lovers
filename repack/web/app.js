'use strict';
const $ = id => document.getElementById(id);
const token = document.querySelector('meta[name=repack-token]').content;
let source = 'files', apps = [], selected = null, lastJobs = '', ready = false, showSetup = false;
let certificate = null, pendingCertificate = null, startingBuild = false, working = false;
let connected = [], appEpoch = 0, appDevice = null, refreshingDevices = false, devicePoll = 0;
const jobTargets = new Map();
let displayedJobs = [];
const preferences = (() => { try { const saved = JSON.parse(localStorage.getItem('repack-preferences') || '{}'); return saved && typeof saved === 'object' ? saved : {}; } catch { return {}; } })();
if (typeof preferences.proxy === 'string') $('proxy').value = preferences.proxy;
if (typeof preferences.certificate_url === 'string') $('certificate-url').value = preferences.certificate_url;
function remember() {
  try { localStorage.setItem('repack-preferences', JSON.stringify({proxy: $('proxy').value, certificate_url: $('certificate-url').value})); } catch { /* Preferences are optional when browser storage is disabled. */ }
}
async function api(path, body = {}) {
  const response = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-Repack-Token': token}, body: JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok) throw Error(data.error || 'Request failed');
  return data;
}
function notice(text) { $('notice').textContent = text || ''; $('notice').hidden = !text; }
function node(tag, text, cls) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (cls) element.className = cls;
  return element;
}
function sourceTab(value) {
  source = value;
  $('file-source').hidden = value !== 'files'; $('device-source').hidden = value !== 'device';
  $('file-device').hidden = value !== 'files';
  $('tab-files').classList.toggle('active', value === 'files'); $('tab-device').classList.toggle('active', value === 'device');
}
$('tab-files').onclick = () => sourceTab('files');
$('tab-device').onclick = () => sourceTab('device');
$('apks').onchange = () => { $('file-summary').textContent = Array.from($('apks').files, file => file.name).join(', ') || 'No files selected.'; };
for (const radio of document.querySelectorAll('input[name=mode]')) radio.onchange = () => {
  $('interception').hidden = radio.value === 'plain';
  if (radio.value === 'interception' && ready) detectCertificate(true);
};
for (const radio of document.querySelectorAll('input[name=ca-source]')) radio.onchange = () => {
  $('ca-url-panel').hidden = radio.value !== 'url'; $('ca-file-panel').hidden = radio.value !== 'upload';
  if (radio.value === 'url' && ready) detectCertificate(true);
};
$('proxy').onchange = remember;
$('certificate-url').onchange = () => { remember(); certificate = null; detectCertificate(true); };
async function getCertificate(url) {
  if (certificate?.url === url) return certificate;
  if (pendingCertificate?.url === url) return pendingCertificate.promise;
  const promise = api('/api/certificate', {url}).then(result => {
    if ($('certificate-url').value === url) certificate = result;
    return result;
  });
  pendingCertificate = {url, promise};
  try { return await promise; } finally { if (pendingCertificate?.promise === promise) pendingCertificate = null; }
}
async function detectCertificate(quiet = false) {
  const url = $('certificate-url').value.trim();
  $('fetch-certificate').disabled = true; $('certificate-status').textContent = 'Checking certificate endpoint…';
  try {
    const result = await getCertificate(url);
    if ($('certificate-url').value.trim() === url) {
      $('certificate-status').textContent = result.provider + ' ready · ' + result.format + ' · SHA-256 ' + result.sha256.slice(0, 16) + '…';
    }
    remember(); return result;
  } catch (error) {
    if ($('certificate-url').value.trim() === url) $('certificate-status').textContent = error.message + ' You can also choose a certificate file below.';
    if (!quiet) throw error;
  } finally { $('fetch-certificate').disabled = false; }
}
$('fetch-certificate').onclick = async () => {
  certificate = null;
  try { await detectCertificate(); notice(''); } catch (error) { notice(error.message); }
};
function deviceOptions(select, preferred, initialDefault = false) {
  select.replaceChildren(node('option', 'Choose a device')); select.firstChild.value = '';
  for (const device of connected) {
    const option = node('option', device.model + ' · ' + device.serial + (device.state === 'device' ? '' : ' · ' + device.state));
    option.value = device.serial; option.disabled = device.state !== 'device'; select.append(option);
  }
  if (preferred && !connected.some(device => device.serial === preferred)) {
    const missing = node('option', preferred + ' · disconnected'); missing.value = preferred; missing.disabled = true; select.append(missing);
  }
  if (preferred) select.value = preferred;
  else if (initialDefault && connected.filter(device => device.state === 'device').length === 1) select.value = connected.find(device => device.state === 'device').serial;
}
async function refreshDevices(quiet = false) {
  if (refreshingDevices) return;
  refreshingDevices = true;
  try {
    const data = await api('/api/devices');
    const changed = JSON.stringify(connected) !== JSON.stringify(data.devices); connected = data.devices;
    for (const id of ['device', 'install-device']) deviceOptions($(id), $(id).value, true);
    if (changed) lastJobs = '';
    if (!quiet && !connected.length) notice('No phone found. Enable USB debugging, connect it, accept the authorization prompt, then refresh.');
  } catch (error) { if (!quiet) notice(error.message); }
  finally { refreshingDevices = false; }
}
$('refresh-devices').onclick = () => refreshDevices();
$('device').onchange = () => {
  appEpoch++; appDevice = null; selected = null; apps = []; renderApps();
  $('selected-app').textContent = 'No app selected.'; $('app-count').textContent = ''; $('icons-status').textContent = '';
};
async function loadIcons(device, user, epoch) {
  let loaded = 0;
  const packages = apps.map(app => app.package);
  for (let i = 0; i < packages.length; i += 20) {
    if (epoch !== appEpoch) return;
    $('icons-status').textContent = 'Loading icons in the background… ' + loaded + '/' + packages.length + '. You can select an app and build now.';
    try {
      const result = await api('/api/app-icons', {device, user, packages: packages.slice(i, i + 20)});
      if (epoch !== appEpoch) return;
      for (const row of result.apps) { const app = apps.find(app => app.package === row.package); if (app) app.icon = row.icon; }
      // Update only the icon: keep search, selection, keyboard focus and scroll usable.
      for (const button of $('apps').querySelectorAll('.app')) {
        const app = apps.find(app => app.package === button.dataset.package);
        if (app?.icon) button.querySelector('.app-icon').replaceWith(appIcon(app));
      }
      loaded += Math.min(20, packages.length - i);
    } catch (error) {
      if (epoch === appEpoch) $('icons-status').textContent = 'Some icons are unavailable. Names and versions are ready to use.';
      return;
    }
  }
  if (epoch === appEpoch) $('icons-status').textContent = 'Icons loaded.';
}
$('load-apps').onclick = async () => {
  const epoch = ++appEpoch;
  try {
    const device = $('device').value;
    if (!device || !connected.some(row => row.serial === device && row.state === 'device')) throw Error('Choose an authorized phone first.');
    notice(''); $('load-apps').disabled = true;
    $('apps').replaceChildren(node('p', 'Reading installed app names and versions…', 'hint')); $('icons-status').textContent = '';
    const data = await api('/api/apps', {device});
    if (epoch !== appEpoch || device !== $('device').value) return;
    apps = data.apps; appDevice = device; selected = null;
    $('selected-app').textContent = 'No app selected.';
    $('app-count').textContent = apps.length + ' apps ready' + (data.elapsed_seconds !== undefined ? ' in ' + data.elapsed_seconds + 's' : '');
    renderApps(); loadIcons(device, data.user, epoch);
  } catch (error) { if (epoch === appEpoch) notice(error.message); }
  finally { $('load-apps').disabled = false; }
};
function appIcon(app) {
  if (app.icon) { const icon = node('img', undefined, 'app-icon'); icon.src = app.icon; icon.alt = ''; icon.width = 42; icon.height = 42; icon.loading = 'lazy'; return icon; }
  return node('span', (app.name || app.package || '?').slice(0, 1).toUpperCase(), 'app-icon fallback');
}
function appVersion(app) { return app.version ? 'v' + app.version + (app.version_code != null ? ' (' + app.version_code + ')' : '') : (app.version_code !== null && app.version_code !== undefined ? 'Build ' + app.version_code : 'Version unavailable'); }
function renderApps() {
  const query = $('search').value.toLocaleLowerCase();
  const matches = apps.filter(app => (app.name + ' ' + app.package).toLocaleLowerCase().includes(query));
  $('apps').replaceChildren();
  for (const app of matches) {
    const button = node('button', undefined, 'app' + (selected?.package === app.package ? ' selected' : ''));
    button.type = 'button'; button.setAttribute('role', 'option'); button.setAttribute('aria-selected', String(selected?.package === app.package));
    button.dataset.package = app.package; button.append(appIcon(app));
    const details = node('span', undefined, 'app-details');
    details.append(node('span', app.name), node('small', appVersion(app), 'app-version'), node('small', app.package)); button.append(details);
    button.onclick = () => { selected = app; $('selected-app').textContent = 'Selected: ' + app.name + ' · ' + appVersion(app) + ' · ' + app.package; renderApps(); };
    $('apps').append(button);
  }
  if (!matches.length) $('apps').append(node('p', apps.length ? 'No matching apps.' : 'No apps loaded yet.', 'hint'));
}
$('search').oninput = renderApps;
$('show-setup').onclick = () => { showSetup = !showSetup; $('setup').hidden = !showSetup; };
$('prepare').onclick = async () => {
  try { notice(''); await api('/api/setup', {jdk: $('jdk').value, sdk: $('sdk').value, accept_sdk_license: $('license').checked}); await poll(); }
  catch (error) { notice(error.message); }
};
async function upload(files) {
  const {id} = await api('/api/uploads');
  for (const file of files) {
    $('activity').textContent = 'Uploading ' + file.name + '…';
    const response = await fetch('/api/uploads/' + id + '/' + encodeURIComponent(file.name), {method: 'POST', headers: {'X-Repack-Token': token, 'Content-Type': 'application/octet-stream'}, body: file});
    const data = await response.json(); if (!response.ok) throw Error(data.error || 'Upload failed');
  }
  return id;
}
$('build').onclick = async () => {
  if (startingBuild || working) return;
  try {
    startingBuild = true; notice(''); $('build').disabled = true;
    const mode = document.querySelector('input[name=mode]:checked').value;
    const caSource = document.querySelector('input[name=ca-source]:checked').value;
    const device = $(source === 'device' ? 'device' : 'install-device').value;
    const options = {mode, device, auto_install: $('auto-install').checked && !!device};
    if (source === 'device' && (!selected || appDevice !== device)) throw Error('Load and select an app from this phone first.');
    if (source === 'files') {
      const chosen = Array.from($('apks').files);
      if (!chosen.length) throw Error('Choose your original APK files.');
      const containers = chosen.filter(file => !file.name.toLowerCase().endsWith('.apk'));
      if (containers.length && chosen.length !== 1) throw Error('Choose one container or a set of APK files.');
      if (containers.length && !device) throw Error('Select a phone to target an APK container.');
    }
    if (mode === 'interception') {
      if ($('antitamper').checked && !device) throw Error('Choose an Android 11 phone for in-app signing-check support.');
      options.proxy = $('proxy').value; options.antitamper = $('antitamper').checked; options.ca_source = caSource;
      if (caSource === 'upload') { if (!$('ca').files.length) throw Error('Choose your public proxy certificate (PEM or DER).'); }
      else { options.ca_id = (await detectCertificate()).id; }
    }
    if (source === 'device') options.package = selected.package;
    else options.upload = await upload($('apks').files);
    if (mode === 'interception' && caSource === 'upload') options.ca_upload = await upload($('ca').files);
    await api('/api/jobs', options); lastJobs = ''; await poll();
  } catch (error) { notice(error.message); }
  finally { startingBuild = false; $('build').disabled = working; $('activity').textContent = ''; }
};
function proxyLabel(proxy) { if (!proxy) return 'None'; return (proxy.host.includes(':') ? '[' + proxy.host + ']' : proxy.host) + ':' + proxy.port; }
function renderJobs(jobs, busy) {
  displayedJobs = jobs;
  $('jobs').replaceChildren();
  if (!jobs.length) { $('jobs').append(node('div', 'Your generated APKs and installation results will appear here.', 'empty')); return; }
  for (const job of jobs) {
    const card = node('article', undefined, 'job'), head = node('div', undefined, 'job-head');
    const app = job.app || {}, title = node('div', undefined, 'build-app-title'), text = node('div');
    title.append(appIcon({...app, package:job.package}));
    text.append(node('h3', app.name || job.package || 'Preparing app…'));
    if (app.name) text.append(node('small', job.package || ''));
    if (app.version || job.version_code !== undefined) text.append(node('small', appVersion({...app, version_code:job.version_code ?? app.version_code})));
    title.append(text);
    const badge = node('span', job.outputs_deleted ? 'APKs deleted' : job.state.replaceAll('_', ' '), 'badge');
    badge.dataset.state = job.state; head.append(title, badge);
    card.dataset.job = job.id;
    card.append(head, node('p', (job.mode === 'plain' ? 'Rebuild-only diagnostic' : 'HTTPS interception') + ' · ' + new Date(job.created * 1000).toLocaleString()), node('p', job.message));
    if (job.progress) {
      const progress = job.progress, steps = node('ol', undefined, 'build-steps');
      card.append(node('p', progress.done ? 'Build complete' : 'Build step ' + (progress.current + 1) + ' of ' + progress.labels.length, 'step-status'));
      progress.labels.forEach((label, index) => steps.append(node('li', label, progress.done || index < progress.current ? 'complete' : index === progress.current ? 'current' : 'pending')));
      card.append(steps);
    }
    if (job.mode === 'interception') {
      card.append(node('p', 'Proxy: ' + proxyLabel(job.proxy), 'build-proxy'));
      if (job.certificate) {
        const info = job.certificate;
        const line = node('p', 'Certificate: ' + (info.url || info.source || info.provider || 'Selected CA') + ' · SHA-256 ' + info.sha256.slice(0, 16) + '…', 'hint');
        line.title = info.sha256; card.append(line);
      }
    } else card.append(node('p', 'Proxy: none · Trust and pinning unchanged', 'hint'));
    if (job.files.length) {
      const bundle = node('a', 'Download APK set (.zip)'); bundle.href = '/api/jobs/' + job.id + '/bundle'; card.append(bundle);
      card.append(node('p', 'To install manually, extract the ZIP and follow INSTALL.txt. Or choose a connected device below.', 'hint'));
    }
    if (job.files.length && !['building', 'installing'].includes(job.state) && !job.outputs_deleted) {
      const preferred = jobTargets.has(job.id) ? jobTargets.get(job.id) : (job.source_device || job.device || '');
      const row = node('div', undefined, 'row'), label = node('label', 'Install this build on', 'grow'), select = node('select');
      deviceOptions(select, preferred); select.setAttribute('aria-label', 'Installation device for ' + (job.package || 'build'));
      select.onchange = () => { jobTargets.set(job.id, select.value); renderJobs(displayedJobs, working); };
      label.append(select); row.append(label);
      const target = select.value, authorized = connected.some(device => device.serial === target && device.state === 'device');
      const pending = job.confirmation_device || job.install_device || job.device;
      if (job.state === 'awaiting_confirmation' && pending === target) {
        card.append(row);
        const box = node('div', undefined, 'confirmation');
        box.append(node('strong', 'Replace ' + job.package + ' on ' + target + '?'), node('p', 'This will uninstall the existing copy and delete its local app data. Original APK backups cannot restore that data.'));
        const consent = node('label', undefined, 'check'), check = node('input'); check.type = 'checkbox';
        consent.append(check, document.createTextNode('I accept deleting this app’s local data on this device.'));
        const button = node('button', 'Replace and install', 'danger'); button.disabled = true;
        check.onchange = () => button.disabled = !check.checked || busy || !authorized;
        button.onclick = () => installJob(job, true, select.value); box.append(consent, button); card.append(box);
      } else {
        const button = node('button', job.state === 'install_failed' ? 'Retry installation' : 'Install on device', 'secondary');
        button.disabled = busy || !authorized; button.onclick = () => installJob(job, false, select.value); row.append(button); card.append(row);
      }
      card.append(node('p', 'Android version and CPU compatibility are checked before installation. The APK set keeps its original split selection.', 'hint'));
    }
    if (!['building', 'installing'].includes(job.state)) {
      const actions = node('div', undefined, 'build-actions');
      if (job.files.length) { const remove = node('button', 'Delete APKs', 'secondary'); remove.disabled = busy; remove.onclick = () => deleteJob(job, 'apks'); actions.append(remove); }
      const removeBuild = node('button', 'Delete build…', 'text-danger'); removeBuild.disabled = busy;
      removeBuild.onclick = () => deleteJob(job, 'build'); actions.append(removeBuild); card.append(actions);
    }
    $('jobs').append(card);
  }
}
async function deleteJob(job, scope) {
  const message = scope === 'apks'
    ? 'Delete the generated APKs for ' + (job.package || 'this build') + '? Original backups and reports will be kept. The installed phone app stays unchanged.'
    : 'Delete this entire build, including generated APKs, original APK backups and logs? The installed phone app and reusable signing key will be kept.';
  if (!window.confirm(message)) return;
  try { await api('/api/jobs/' + job.id + '/delete', {scope}); lastJobs = ''; await poll(); notice(''); }
  catch (error) { notice(error.message); }
}
async function installJob(job, confirmed, device) {
  try { notice(''); await api('/api/jobs/' + job.id + '/install', {confirm_wipe: confirmed, package: job.package, device}); lastJobs = ''; await poll(); }
  catch (error) { notice(error.message); }
}
async function poll() {
  try {
    const response = await fetch('/api/status', {headers: {'X-Repack-Token': token}});
    if (!response.ok) throw Error('Unable to read local status. Refresh the page.');
    const data = await response.json();
    const preparing = data.setup.state === 'preparing';
    $('loading').hidden = !preparing; $('show-setup').disabled = preparing;
    $('setup').hidden = preparing || (data.setup.state === 'ready' && !showSetup); $('workspace').hidden = data.setup.state !== 'ready';
    $('setup-status').textContent = data.setup.message; $('prepare').disabled = data.setup.state === 'preparing';
    if (!$('jdk').value) $('jdk').value = data.discovery.jdk;
    if (!$('sdk').value) $('sdk').value = data.discovery.sdk;
    $('sdk-source').textContent = 'SDK: ' + data.discovery.sdk_source + ' · ' + data.discovery.sdk;
    working = data.busy; $('build').disabled = working || startingBuild; $('activity').textContent = data.busy ? 'Working locally…' : '';
    const snapshot = JSON.stringify({jobs: data.jobs, busy: data.busy});
    if (snapshot !== lastJobs) { renderJobs(data.jobs, data.busy); lastJobs = snapshot; }
    if (!ready && data.setup.state === 'ready') { ready = true; detectCertificate(true); await refreshDevices(true); }
    else if (ready && ++devicePoll % 5 === 0) refreshDevices(true);
  } catch (error) { notice(error.message); }
}
poll(); setInterval(poll, 1200);
