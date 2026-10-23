import { api, esc, toast } from './core.js';
import { onAction, onChange } from './delegate.js';
import { help } from './help.js';

// ---------------- Setup ----------------
// Categories with BOTH a size and an age cap, in display order. This is the
// single source for the retention table and for saveRetention — they were two
// hardcoded lists, so a category added to one rendered an input that silently
// never saved.
//
// `rawUpload` ("Staged uploads") is deliberately NOT here. Staged files are
// deleted twice over without anyone asking: inline by the media pipeline the
// moment an upload is filed, and by the sweeper for orphans whose metadata
// never arrived — with a code-level one-hour floor a panel edit cannot lower.
// It was a setting for a failure mode nobody can observe, over a dot-directory
// no screen in this app can browse. The server-side default stays.
//
// `wasteCheck` and `healthPic` ARE here now: both are photo galleries the
// Timeline renders, so they are the categories most likely to be the ones
// filling a disk, and they had no control at all while two internal caches did.
const RETENTION_LABELS = {
  fullVideo: 'Recordings',
  eventImage: 'Snapshots',
  highLight: 'Highlights',
  dynamicVideo: 'Motion Clips',
  cloudDouble: 'Timelapses',
  wasteCheck: 'Waste photos',
  healthPic: 'Health photos',
  deviceLog: 'Device logs',
  thumbnail: 'Thumbnail cache',
};
function numOrNull(id) {
  const v = document.getElementById(id).value;
  return v === '' ? null : Number(v);
}
onAction('save-retention', () => saveRetention());
async function saveRetention() {
  const body = {};
  for (const k of Object.keys(RETENTION_LABELS))
    body[k] = { max_mb: numOrNull('ret_' + k + '_mb'), max_days: numOrNull('ret_' + k + '_days') };
  // Age-only categories: rows of their own rather than RETENTION_LABELS
  // entries, which carry a size cap these two do not have.
  body.events = { max_days: numOrNull('ret_events_days') };
  body.blocked = { max_days: numOrNull('ret_blocked_days') };
  const r = await api('retention', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  toast(r.ok ? 'Retention saved' : 'Error: ' + (r.error || 'failed'));
}

// The proxy guards stay VISIBLE but disabled while proxy mode is off: hiding
// "RCE guard is on" would be worse than showing it inactive. The upstream
// picker and the blocked-attempts table are hidden outright — they say nothing
// at all when nothing is being forwarded.
const CUSTOM_UPSTREAM = '__custom__';

async function loadSetup() {
  const i = await api('info');
  // No `api('devices')` here: this tab used to repeat the Devices tab's own
  // table verbatim from the same array. `api('info')` already carries the
  // device count, which is the only thing Setup actually needs to say.
  const ret = await api('retention');
  const v = document.getElementById('setupView');
  const s = i.settings || {};
  const w = i.settings_writable;
  const rd = ret.retention || {};
  const on = s.proxy_mode;
  const sw = (key, val, enabled) =>
    `<span class="sw"><input type="checkbox" ${val ? 'checked' : ''} ${w && enabled !== false ? '' : 'disabled'} data-change="save-setting" data-key="${esc(key)}"><span class="sl"></span></span>`;
  // A guard row that greys out with proxy mode, rather than disappearing.
  const guard = (key, val, title, hint) =>
    `<label class="ctrl${on ? '' : ' disabled'}"><span>${title}<br><span class="mut" style="font-size:11px">${hint}</span></span>${sw(key, val, on)}</label>`;

  // An empty setting means the server's default, which it flags for us — the
  // picker must not have to guess which key that is.
  const presets = i.upstreams || [];
  const fallback = (presets.find(u => u.default) || presets[0] || {}).key || '';
  const current = s.proxy_upstream || fallback;
  const sel = presets.some(u => u.key === current) ? current : CUSTOM_UPSTREAM;

  v.innerHTML = `
  <div class="card"><h3>Settings${help(
    'Proxy mode and capture live here and nowhere else — they are not configuration options. Both apply immediately and survive a restart.',
  )}${w ? '' : ' <span class="badge warn">read-only — running outside Home Assistant</span>'}</h3>
    <div class="ctrls">
      <label class="ctrl"><span>Proxy mode<br><span class="mut" style="font-size:11px">forward every device request to the real PetKit cloud and answer with its reply</span></span>${sw('proxy_mode', s.proxy_mode)}</label>
      <label class="ctrl"><span>Traffic capture<br><span class="mut" style="font-size:11px">record HTTP + MQTT to JSONL (see Capture tab)</span></span>${sw('capture', s.capture)}</label>
    </div>
    ${
      on
        ? `<div style="margin-top:14px"><label class="mut">Upstream server</label>
      <span class="cn" style="display:flex;gap:6px;margin-top:4px;flex-wrap:wrap">
        <select id="proxyUpSel" ${w ? '' : 'disabled'} data-change="save-upstream">
          ${presets.map(u => `<option value="${esc(u.key)}" ${sel === u.key ? 'selected' : ''}>${esc(u.key)} — ${esc(u.url)}</option>`).join('')}
          <option value="${CUSTOM_UPSTREAM}" ${sel === CUSTOM_UPSTREAM ? 'selected' : ''}>custom…</option>
        </select>
      </span>
      ${
        sel === CUSTOM_UPSTREAM
          ? `<span class="cn" style="display:flex;gap:6px;margin-top:6px">
        <input id="proxyUp" value="${esc(s.proxy_upstream)}" ${w ? '' : 'disabled'} placeholder="https://api-eu.petkt.com/6/">
        <button class="mini" ${w ? '' : 'disabled'} data-action="save-proxy-upstream">Set</button></span>`
          : ''
      }
      <label class="mut" style="display:block;margin-top:10px">DNS for upstream lookups${help(
        'Only used to find the server above. Leave empty unless your router or Pi-hole points PetKit’s names at this app — then it would point them here for us too, and proxy mode would reach itself instead of the cloud.',
      )}</label>
      <span class="cn" style="display:flex;gap:6px;margin-top:4px">
        <input id="proxyDns" value="${esc(s.proxy_dns || '')}" ${w ? '' : 'disabled'} placeholder="empty = system resolver">
        <button class="mini" ${w ? '' : 'disabled'} data-action="save-proxy-dns">Set</button></span>
    </div>`
        : ''
    }
    <p class="sub" style="margin-top:14px">${on ? 'Removed from the cloud’s replies:' : 'Guards for proxy mode — inactive until it is on.'}</p>
    <div class="ctrls">
      ${guard('proxy_block_run_cmd', 'proxy_block_run_cmd' in s ? s.proxy_block_run_cmd : true, 'Block run_cmd <span class="badge warn">RCE guard</span>', 'strip shell commands the cloud tries to run on the device')}
      ${guard('proxy_block_ota', 'proxy_block_ota' in s ? s.proxy_block_ota : true, 'Block OTA push <span class="badge warn">firmware guard</span>', 'answer the OTA endpoints locally; drop firmware images found elsewhere')}
      ${guard('proxy_block_log_upload', 'proxy_block_log_upload' in s ? s.proxy_block_log_upload : true, 'Block log upload <span class="badge warn">privacy</span>', 'withhold the token the device needs to send its debug log to PetKit')}
      ${guard('proxy_mqtt_bridge', 'proxy_mqtt_bridge' in s ? s.proxy_mqtt_bridge : true, 'Upstream MQTT bridge', 'also bridge the device’s MQTT session to the real Aliyun broker')}
      ${guard('proxy_media_real_oss', !!s.proxy_media_real_oss, 'Media → real OSS', 'let the device upload recordings to PetKit instead of us — nothing lands locally')}
      ${guard('proxy_local_cvr_window', !!s.proxy_local_cvr_window, 'Keep recording locally', 'ignore the cloud’s subscription window and tell the camera its storage is active — a lapsed PetKit plan otherwise stops recording with no error anywhere')}
    </div>
    ${on ? upstreamStatus(i.upstream || {}) : ''}
    ${on ? `<div id="blockedView" style="margin-top:14px"></div>` : ''}
  </div>
  <div class="card"><h3>Connection <span class="badge">restart to change</span></h3>
    <p class="sub">Bound at startup — set these in the <b>Configuration</b> tab, then restart.</p>
    <table><tbody>
      <tr><td>Version</td><td><code>${esc(i.version || '?')}</code></td><td class="mut">The code actually running. If an update did not take effect this still shows the old number, which is the quickest way to tell a stale build from a real bug.</td></tr>
      <tr><td>API URL (apiServers)</td><td><code>${esc(i.api_url)}</code></td><td class="mut">The URL a device calls. Most models take it over Bluetooth from the Provision tab; the oldest, which have no Bluetooth setup, need a DNS redirect.</td></tr>
      <tr><td>MQTT host</td><td><span class="badge ok">automatic</span></td><td class="mut">No global setting — every device is handed our own broker (derived from the API URL host), except the T3/T4/D4, which are kept on HTTP (<code>esp32_http_only</code>). A patched <code>ctrl</code> connects over MQTT; an unpatched one simply heartbeats over HTTP (it does not crash). Commands fall back to the HTTP heartbeat when there\'s no live MQTT session.</td></tr>
      <tr><td>MQTT broker port</td><td><code>${esc(i.mqtt_port)}</code>${i.mqtt_tls ? ` · TLS <code>${esc(i.mqtt_tls_port)}</code>` : ''}</td><td class="mut">TLS cert ${i.cert_exists ? '<span class="badge ok">present</span>' : '<span class="badge bad">missing</span>'}${help('The self-signed certificate the broker presents. "missing" means the file named by cert_path is not there, and a device that expects TLS will not connect.')}</td></tr>
      <tr><td>MQTT auth</td><td>${i.strict_auth ? '<span class="badge warn">strict HMAC</span>' : '<span class="badge">accept-all</span>'}</td><td class="mut">Accept-all is fine for a trusted LAN; strict enforces the Aliyun HMAC-SHA256 sign.</td></tr>
      <tr><td>Bridge → HA</td><td>${
        !i.ha_enabled
          ? '<span class="badge">disabled</span>'
          : i.ha_publishing
            ? '<span class="badge ok">publishing</span>'
            : '<span class="badge bad">down</span>'
      }</td><td class="mut">Whether entities are reaching Home Assistant right now.${help('This is the connection to HOME ASSISTANT\'s broker, not the one your devices talk to — a device can be perfectly healthy while this is down, and vice versa. "disabled" means publishing was switched off (no ha_mqtt_host, or --no-ha), which is a valid way to run.')}</td></tr>
    </tbody></table>
  </div>
  <div class="card"><h3>Media Retention${help(
    'Over the size cap, the oldest files go first; past the age cap they go regardless of size. The sweep runs about every 10 minutes. Leave a field blank for no cap — 0 also means no cap, not "delete everything".',
  )}</h3>
    <table><thead><tr><th></th><th>Max size (MB)</th><th>Max age (days)</th></tr></thead><tbody>
      ${Object.keys(RETENTION_LABELS)
        .map(k => {
          const c = rd[k] || {};
          return `<tr><td>${RETENTION_LABELS[k]}</td>
        <td><input type="number" id="ret_${k}_mb" value="${esc(c.max_mb ?? '')}" min="0" style="width:100px"></td>
        <td><input type="number" id="ret_${k}_days" value="${esc(c.max_days ?? '')}" min="0" style="width:100px"></td></tr>`;
        })
        .join('')}
      <tr><td>Events (history)</td><td class="mut">—</td><td><input type="number" id="ret_events_days" value="${esc((rd.events || {}).max_days ?? '')}" min="0" style="width:100px"></td></tr>
      <tr><td>Blocked attempts${help('How long to keep the record of instructions the real cloud sent that we refused. Rows are tiny and rare, so a long window costs almost nothing and is worth having if you ever need to show what happened.')}</td><td class="mut">—</td><td><input type="number" id="ret_blocked_days" value="${esc((rd.blocked || {}).max_days ?? '')}" min="0" style="width:100px"></td></tr>
    </tbody></table>
    <div style="margin-top:10px"><button class="act" data-action="save-retention">Save retention settings</button></div>
  </div>
  <div class="card"><h3>Import configuration${help(
    'A JSON file of PetKit’s own replies to each device — dev_signup, dev_device_info, dev_feed_get, dev_schedule_get, dev_multi_config, dev_k3_device_info — as a capture of the device talking to PetKit holds them. The format is in the documentation.',
  )}</h3>
    <p class="sub">Settings, schedules and the Pura Air pairing PetKit holds for a device, so it keeps them here. Import <b>before</b> redirecting the device: a litter box adopts whatever settings it is served at boot, and a feeder that fetches an empty schedule stops feeding.</p>
    <input type="file" id="importFile" accept=".json,application/json">
    <button class="act" data-action="import-config">Import</button>
    <div id="importResult" style="margin-top:10px"></div>
  </div>`;
  if (on) loadBlocked(i.redactions || {});
}
onAction('import-config', async el => {
  const file = document.getElementById('importFile').files[0];
  if (!file) return toast('Choose a file first');
  let doc;
  try {
    doc = JSON.parse(await file.text());
  } catch {
    return toast('Error: that file is not JSON');
  }
  el.disabled = true;
  const r = await api('import', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(doc),
  });
  el.disabled = false;
  if (r.error) return toast('Error: ' + r.error);
  // One line per device, refusals and skipped parts included: an import that
  // quietly drops a schedule is worse than one that says so.
  document.getElementById('importResult').innerHTML = (r.devices || [])
    .map(d =>
      d.error
        ? `<div><span class="badge bad">refused</span> ${esc(d.type || '?')}: ${esc(d.error)}</div>`
        : `<div><span class="badge ok">${d.created ? 'added' : 'updated'}</span> ${esc(d.type)} ${esc(d.id)}: ${esc(d.imported.join(', ') || 'nothing')}${
            d.skipped.length
              ? ` <span class="mut">— skipped ${esc(d.skipped.map(s => `${s.part} (${s.reason})`).join('; '))}</span>`
              : ''
          }</div>`,
    )
    .join('');
  toast('Import done');
});
onChange('save-setting', el => saveSetting(el.dataset.key, el.checked));
// "custom…" only reveals the text box; nothing is saved until a real value is
// picked, so switching to it does not blank a working upstream.
onChange('save-upstream', el =>
  el.value === CUSTOM_UPSTREAM ? renderCustomUpstream() : saveSetting('proxy_upstream', el.value),
);
onAction('save-proxy-dns', () =>
  saveSetting('proxy_dns', document.getElementById('proxyDns').value),
);
onAction('save-proxy-upstream', () =>
  saveSetting('proxy_upstream', document.getElementById('proxyUp').value),
);
function renderCustomUpstream() {
  const sel = document.getElementById('proxyUpSel');
  if (sel && !document.getElementById('proxyUp')) {
    sel.parentElement.insertAdjacentHTML(
      'afterend',
      '<span class="cn" style="display:flex;gap:6px;margin-top:6px"><input id="proxyUp" placeholder="https://api.eu-pet.com/6/">' +
        '<button class="mini" data-action="save-proxy-upstream">Set</button></span>',
    );
    document.getElementById('proxyUp').focus();
  }
}
async function saveSetting(key, value) {
  const r = await api('settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ [key]: value }),
  });
  toast(r.ok ? 'Saved · ' + key : 'Error: ' + (r.error || 'failed'));
  loadSetup(); // re-render (guards ungrey, the upstream picker appears, …)
}

// Once a taken-over device settles down it polls only the heartbeat, PetKit
// refuses that, and we answer locally — so nothing in the UI would otherwise
// differ from proxy being off. This line is what says it is running.
function upstreamStatus(counts) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (!total)
    return '<p class="sub" style="margin-top:14px"><span class="mut">No calls forwarded yet — the device polls every ~10s.</span></p>';
  const ok = counts.ok || 0;
  const refused = Object.entries(counts).filter(([k]) => k.startsWith('error_'));
  const failed = Object.entries(counts).filter(([k]) => k.startsWith('http_'));
  let html =
    `<p class="sub" style="margin-top:14px">Forwarded <b>${total}</b> calls · ` +
    `<span class="badge ${ok ? 'ok' : ''}">${ok} answered</span> ` +
    refused
      .map(([k, n]) => `<span class="badge warn">${n} refused (${esc(k.slice(6))})</span>`)
      .join(' ') +
    failed
      .map(([k, n]) => `<span class="badge bad">${n} × HTTP ${esc(k.slice(5))}</span>`)
      .join(' ') +
    '</p>';
  if (refused.length && !ok)
    html +=
      '<p class="sub mut">The cloud is refusing every session-bearing call — expected once this app ' +
      'has taken the device over, since the session it presents is one we issued. The device is served our own answers throughout.</p>';
  return html;
}

// Blocked attempts are the persisted ones only. The routine rewrites — every
// dev_serverinfo poll substitutes our address — are counters, not rows.
const REDACT_LABELS = {
  rce: 'shell command',
  ota: 'firmware push',
  secret: 'credential swap',
  log_upload: 'log upload',
  server: 'server address',
  mqtt: 'broker address',
  oss_sts: 'media upload',
  locale: 'timezone',
};
async function loadBlocked(counts) {
  const v = document.getElementById('blockedView');
  if (!v) return;
  let r;
  try {
    r = await api('blocked?limit=25');
  } catch (e) {
    v.innerHTML = '';
    return;
  }
  if (r.error) {
    v.innerHTML = '';
    return;
  }
  // Only rendered when there is something to render. The counter chips that
  // used to head this section were dominated by routine rewrites — the server
  // address, the MQTT host, STS, the timezone — which fire on every poll, so
  // they scrolled a permanent "nothing is wrong" banner past the one thing
  // worth seeing. A blocked attempt is a cloud instruction we REFUSED (a shell
  // command, a firmware push, a credential swap); on a healthy session there
  // are none and this whole card should be absent, not saying so at length.
  const rows = r.records || [];
  if (!rows.length) {
    v.innerHTML = '';
    return;
  }
  v.innerHTML =
    `<h3 style="margin-top:0">Blocked attempts <span class="badge bad">${esc(rows.length)}</span>${help(
      'Instructions the real PetKit cloud sent that this app refused to pass on to your device. Kept in the database, so this list outlives a restart.',
    )}</h3>
    <table><thead><tr><th>When</th><th>What</th><th>Endpoint</th><th>Payload</th></tr></thead><tbody>` +
    rows
      .map(
        b => `<tr><td class="mut">${esc(new Date((b.created_at || 0) * 1000).toLocaleString())}</td>
        <td><span class="badge bad">${esc(REDACT_LABELS[b.kind] || b.kind)}</span></td>
        <td><code>${esc(b.endpoint || '')}</code></td>
        <td class="mut">${esc(b.payload_json || '')}</td></tr>`,
      )
      .join('') +
    '</tbody></table>';
}

export { loadSetup };
