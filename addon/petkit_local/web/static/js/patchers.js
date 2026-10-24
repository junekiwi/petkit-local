import { api, esc, toast, fmtBytes } from './core.js';
import { onAction } from './delegate.js';

// ---------------- Patchers ----------------
async function loadPatchers() {
  const ds = await api('devices');
  const v = document.getElementById('patchView');
  if (!ds.length) {
    v.innerHTML =
      '<div class="empty"><b>No devices connected</b><p class="mut">Connect a device first, then come back to apply patches.</p></div>';
    return;
  }
  let html = `<div class="card" style="border-color:var(--warn)">
    <p style="margin:0"><b>Warning: firmware modification</b> — These patchers modify files on the device filesystem. This is done at your own risk. The authors are not responsible for any bricking, damage, loss of warranty, or other issues. Read each description carefully before applying.</p>
    <p style="margin:4px 0 0;font-size:0.85em;opacity:0.8">All patches are stored on the writable /system partition (jffs2). The read-only /app partition (squashfs) is never modified. Removing a patch just deletes the files from /system and reboots — the device returns to stock firmware.</p></div>`;
  for (const dev of ds) {
    const p = await api('devices/' + dev.id + '/patcher');
    if (!p.supported) {
      const fw = await api('devices/' + dev.id + '/firmware');
      html += fw.supported
        ? firmwareCard(dev, fw)
        : `<div class="card"><h3>${esc(dev.name)} <span class="chip">${esc(dev.type.toUpperCase())} · #${esc(dev.id)}</span></h3><p class="mut">Patchers are only available for the Linux models (T5, T6, T7, D4H, D4SH, W7H), and firmware patching for the T3, T4 and D4. This device uses a different platform.</p></div>`;
      continue;
    }
    const ip = p.device_ip || '?';
    html += `<div class="card"><h3>${esc(dev.name)} <span class="chip">${esc(dev.type.toUpperCase())} · #${esc(dev.id)}</span></h3>`;
    if (!ip || ip === '?')
      html +=
        '<p class="badge warn">Device IP unknown — wait for a state_report before patching.</p>';
    for (const [pid, pt] of Object.entries(p.patchers || {})) {
      // Real newlines in the description are rendered by `white-space:pre-line`;
      // only the literal two-character sequence "\n" becomes a <br>. Splitting
      // first and escaping each piece keeps that without ever un-escaping.
      const desc = String(pt.description ?? '')
        .split('\\n')
        .map(esc)
        .join('<br>');
      html += `<div class="card" style="margin:8px 0;background:var(--card2)">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          <b>${esc(pt.name)}</b>
          ${pt.applied ? '<span class="badge ok">applied</span>' : '<span class="badge">not applied</span>'}
          ${pt.unavailable ? `<span class="badge warn">${esc(pt.unavailable)}</span>` : pt.greyed ? '<span class="badge ok">MQTT connected</span>' : ''}
          <span class="grow"></span>
          <span class="badge" title="Checked on the device before anything is written. The exact requirement is measured at apply time and is usually smaller.">needs ~${esc(fmtBytes(pt.needs_bytes))} free on /system</span>
        </div>
        <p class="sub" style="white-space:pre-line">${desc}</p>
        ${pt.needs_pubkey ? `<div style="margin-bottom:8px"><label class="mut">Public key</label><input type="text" class="ssh-pubkey" data-dev="${esc(dev.id)}" data-patcher="${esc(pid)}" placeholder="ssh-rsa AAAA... or ecdsa-sha2-..." value="${esc(pt.ssh_pubkey || '')}" aria-label="Public key"></div>` : ''}
        <div>
          <button class="act${pt.greyed ? ' ghost' : ''}" ${pt.greyed || !ip || ip === '?' ? 'disabled' : ''} data-action="apply-patch" data-id="${esc(dev.id)}" data-patcher="${esc(pid)}" data-name="${esc(pt.name)}">Apply</button>
          <button class="ghost act" data-action="remove-patch" data-id="${esc(dev.id)}" data-patcher="${esc(pid)}" data-name="${esc(pt.name)}">Remove</button>
        </div>
        <pre id="plog_${esc(dev.id)}_${esc(pid)}" style="display:none;margin-top:8px;font-size:11px;max-height:200px;overflow:auto"></pre>
      </div>`;
    }
    html += '</div>';
  }
  v.innerHTML = html;
}
// ESP32 models (T3/T4/D4) have no filesystem to patch: the whole firmware is
// rebuilt with our CA in place of PetKit's and flashed over OTA.
function firmwareCard(dev, fw) {
  const id = esc(dev.id);
  const rel = fw.release;
  const job = fw.job;
  const last = fw.last_result;
  const rows = [
    ['Device reports', esc(fw.firmware || 'unknown')],
    [
      'Stored here',
      rel
        ? `${esc(rel.version)} — ${rel.modules.map(m => esc(m.module)).join(', ')}`
        : 'nothing yet — fetch it from PetKit first',
    ],
    ['Flashed from here', esc(fw.running || 'never')],
  ];
  if (job)
    rows.push([
      'Job',
      `<span class="badge warn">${esc(job.target)} ${esc(job.version)} — ${job.started_at ? 'flashing' : 'waiting for the device'}</span>`,
    ]);
  if (last)
    rows.push([
      'Last job',
      `<span class="badge ${last.ok ? 'ok' : 'warn'}">${esc(last.target)}: ${last.ok ? 'done' : 'failed'}</span> <span class="mut">${esc(last.detail)}</span>`,
    ]);
  if (fw.ca_sha256) rows.push(['CA (SHA-256)', `<code>${esc(fw.ca_sha256.slice(0, 16))}…</code>`]);
  return `<div class="card"><h3>${esc(dev.name)} <span class="chip">${esc(dev.type.toUpperCase())} · #${id}</span></h3>
    <p class="sub">Local MQTT needs this device to trust a certificate this app holds the key to. That certificate is compiled into its firmware, so the whole firmware is rebuilt — PetKit's own image with that one certificate swapped — and flashed over the air. The device keeps the firmware it was running in its other partition, and falls back to it if the new one ever fails to start. PetKit's image is also kept here, and <b>Roll back</b> flashes it back the same way. Keep the device powered while it flashes.</p>
    <table class="stbl"><tbody>${rows.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${v}</td></tr>`).join('')}</tbody></table>
    <div style="margin-top:8px">
      <button class="ghost act" data-action="fw-action" data-fw="fetch" data-id="${id}">Fetch from PetKit</button>
      <button class="act" ${rel && !job ? '' : 'disabled'} data-action="fw-action" data-fw="flash" data-id="${id}">Flash patched</button>
      <button class="ghost act" ${rel && !job ? '' : 'disabled'} data-action="fw-action" data-fw="rollback" data-id="${id}">Roll back to stock</button>
      ${job ? `<button class="ghost act" data-action="fw-action" data-fw="cancel" data-id="${id}">Cancel job</button>` : ''}
    </div>
    <pre id="plog_${id}_esp32fw" style="display:none;margin-top:8px;font-size:11px;max-height:200px;overflow:auto"></pre>
  </div>`;
}
const FW_CONFIRM = {
  flash:
    'Flash the patched firmware to this device?\n\nIt is reflashed over the air. Keep it powered until the log says done.',
  rollback:
    "Flash PetKit's stock firmware back to this device?\n\nIt is reflashed over the air. Keep it powered until the log says done.",
};
onAction('fw-action', async el => {
  const id = Number(el.dataset.id);
  const action = el.dataset.fw;
  if (FW_CONFIRM[action] && !confirm(FW_CONFIRM[action])) return;
  const lg = document.getElementById('plog_' + id + '_esp32fw');
  if (lg) lg.style.display = 'block';
  const r = await api('devices/' + id + '/firmware', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action }),
  });
  if (!r.ok) {
    toast('Error: ' + (r.error || 'failed'));
    if (lg) lg.textContent += 'ERROR: ' + (r.error || 'failed') + '\n';
  } else if (action !== 'fetch') loadPatchers();
});
onAction('apply-patch', el =>
  applyPatch(Number(el.dataset.id), el.dataset.patcher, el.dataset.name),
);
onAction('remove-patch', el =>
  removePatch(Number(el.dataset.id), el.dataset.patcher, el.dataset.name),
);
async function applyPatch(id, patcher, name) {
  if (
    !confirm(
      'Apply "' +
        name +
        '" to this device?\n\nThis modifies the device firmware. Make sure you understand what it does. Proceed?',
    )
  )
    return;
  const lg = document.getElementById('plog_' + id + '_' + patcher);
  if (lg) {
    lg.style.display = 'block';
    lg.textContent = 'Starting...\n';
  }
  toast('Applying ' + name + '...');
  const r = await api('devices/' + id + '/patcher', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      patcher,
      action: 'apply',
      pubkey:
        (document.querySelector(`.ssh-pubkey[data-patcher="${patcher}"][data-dev="${id}"]`) || {})
          .value || '',
    }),
  });
  if (!r.ok) {
    toast('Error: ' + (r.error || 'failed'));
    if (lg) lg.textContent += 'ERROR: ' + (r.error || 'failed') + '\n';
  }
}
async function removePatch(id, patcher, name) {
  if (!confirm('Remove "' + name + '" from this device?\n\nThe device will reboot.')) return;
  const lg = document.getElementById('plog_' + id + '_' + patcher);
  if (lg) {
    lg.style.display = 'block';
    lg.textContent = 'Removing...\n';
  }
  const r = await api('devices/' + id + '/patcher', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ patcher, action: 'remove' }),
  });
  if (!r.ok) {
    toast('Error: ' + (r.error || 'failed'));
  }
}

export { loadPatchers };
