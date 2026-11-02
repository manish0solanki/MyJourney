/*
 * Our Baby Plan — a private, offline, password-protected conception journal.
 *
 * Privacy model:
 *  - All data lives only in this browser's localStorage. Nothing is sent anywhere
 *    (the page's Content-Security-Policy blocks all network connections).
 *  - Data is encrypted with AES-256-GCM using a key derived from your password
 *    (PBKDF2-SHA256, 310,000 iterations). Without the password the data is unreadable.
 *  - The password itself is never stored. If it is forgotten, the data cannot be recovered.
 *
 * Not a medical device and NOT a method of contraception.
 */
'use strict';

/* =========================================================
 * Utilities
 * ======================================================= */
const VAULT_KEY = 'obp.vault.v1';
const PBKDF2_ITER = 310000;
const app = document.getElementById('app');

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const pad = (n) => String(n).padStart(2, '0');
const iso = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const parse = (s) => { const [y, m, d] = s.split('-').map(Number); return new Date(y, m - 1, d, 12); };
const addDays = (s, n) => { const d = parse(s); d.setDate(d.getDate() + n); return iso(d); };
const diff = (a, b) => Math.round((parse(a) - parse(b)) / 864e5); // a - b in days
const today = () => iso(new Date());
const isDate = (s) => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s);
const nice = (s) => parse(s).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
const niceLong = (s) => parse(s).toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' });
const wd = (s) => parse(s).toLocaleDateString(undefined, { weekday: 'short' });
const minD = (a, b) => (a < b ? a : b);
const maxD = (a, b) => (a > b ? a : b);
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;

function toast(msg) {
  document.querySelectorAll('.toast').forEach((t) => t.remove());
  const t = document.createElement('div');
  t.className = 'toast';
  t.setAttribute('role', 'status');
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2200);
}

/* =========================================================
 * Encryption (Web Crypto)
 * ======================================================= */
function b64(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function deriveKey(password, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function sealVault(key, salt, iter, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(data)));
  return { app: 'our-baby-plan', v: 1, iter, salt: b64(salt), iv: b64(iv), ct: b64(ct) };
}

async function openVault(vault, password) {
  const salt = unb64(vault.salt);
  const key = await deriveKey(password, salt, vault.iter);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(vault.iv) }, key, unb64(vault.ct));
  return { key, salt, iter: vault.iter, data: JSON.parse(new TextDecoder().decode(pt)) };
}

function loadVault() {
  try {
    const raw = localStorage.getItem(VAULT_KEY);
    if (!raw) return null;
    const v = JSON.parse(raw);
    return v && v.ct && v.salt && v.iv ? v : null;
  } catch { return null; }
}

/* =========================================================
 * Session & persistence
 * ======================================================= */
let S = null; // { key, salt, iter, data }
let view = 'today';
let journalDate = today();
let calMonth = today().slice(0, 7);
let lastActivity = Date.now();
let saveChain = Promise.resolve();

function defaultData() {
  return {
    version: 1,
    created: today(),
    profile: {
      herName: '', hisName: '', herAge: 36, hisAge: 35,
      tryingSince: '', cycleLength: 28, periodLength: 5, lutealLength: 14,
      tempUnit: 'C', autoLock: 5,
    },
    periods: [], // { start: 'YYYY-MM-DD', end?: 'YYYY-MM-DD' }
    days: {},    // 'YYYY-MM-DD' -> journal entry
    checklist: {},
  };
}

function normalise(data) {
  const d = Object.assign(defaultData(), data || {});
  d.profile = Object.assign(defaultData().profile, d.profile || {});
  d.periods = Array.isArray(d.periods) ? d.periods.filter((p) => p && isDate(p.start)) : [];
  d.days = d.days && typeof d.days === 'object' ? d.days : {};
  d.checklist = d.checklist && typeof d.checklist === 'object' ? d.checklist : {};
  return d;
}

function save() {
  if (!S) return Promise.resolve();
  const snap = { key: S.key, salt: S.salt, iter: S.iter, data: JSON.parse(JSON.stringify(S.data)) };
  saveChain = saveChain
    .then(() => sealVault(snap.key, snap.salt, snap.iter, snap.data))
    .then((v) => localStorage.setItem(VAULT_KEY, JSON.stringify(v)))
    .catch((e) => { console.error(e); toast('Could not save — storage may be full or blocked'); });
  return saveChain;
}

function lock(reason) {
  S = null;
  ENG = null;
  document.body.classList.add('locked');
  renderAuth(reason);
}

['pointerdown', 'keydown', 'touchstart', 'scroll'].forEach((ev) =>
  window.addEventListener(ev, () => { lastActivity = Date.now(); }, { passive: true }));

function checkIdle() {
  if (!S) return;
  const mins = +S.data.profile.autoLock || 5;
  if (Date.now() - lastActivity > mins * 60000) lock('Locked automatically after inactivity.');
}
setInterval(checkIdle, 10000);
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') checkIdle(); });

/* =========================================================
 * Cycle engine
 * ======================================================= */
let ENG = null;

function cycleStats() {
  const p = S.data.profile;
  const starts = [...new Set(S.data.periods.map((x) => x.start))].sort();
  const lens = [];
  for (let i = 1; i < starts.length; i++) {
    const l = diff(starts[i], starts[i - 1]);
    if (l >= 18 && l <= 50) lens.push(l);
  }
  const recent = lens.slice(-6);
  const fallback = Math.min(45, Math.max(20, +p.cycleLength || 28));
  const avg = recent.length ? Math.round(recent.reduce((a, b) => a + b, 0) / recent.length) : fallback;
  const min = recent.length ? Math.min(...recent) : avg;
  const max = recent.length ? Math.max(...recent) : avg;
  return { starts, lens: recent, avg, min, max, irregular: recent.length >= 3 && max - min > 7 };
}

/** Ovulation signals inside [start, endExclusive): first positive OPK and a BBT thermal shift. */
function signals(start, endEx) {
  const unit = S.data.profile.tempUnit;
  const keys = Object.keys(S.data.days).filter((k) => k >= start && k < endEx).sort();
  let opk = null, preg = null;
  const temps = [];
  for (const k of keys) {
    const d = S.data.days[k];
    if (!opk && (d.opk === 'positive' || d.opk === 'peak')) opk = k;
    if (d.test === 'positive') preg = k;
    const t = parseFloat(d.bbt);
    if (!isNaN(t) && t > (unit === 'F' ? 90 : 33) && t < (unit === 'F' ? 105 : 40)) temps.push({ date: k, t });
  }
  // Classic "3 over 6" rule: three temperatures above the highest of the previous six,
  // with the third at least 0.2 °C (≈0.3 °F) above that coverline.
  const rise = unit === 'F' ? 0.3 : 0.2;
  let shift = null, cover = null;
  for (let i = 6; i + 2 < temps.length; i++) {
    const m = Math.max(...temps.slice(i - 6, i).map((x) => x.t));
    if (temps[i].t > m && temps[i + 1].t > m && temps[i + 2].t >= m + rise - 1e-9) {
      shift = temps[i].date; cover = m; break;
    }
  }
  return { opk, shift, cover, temps, preg };
}

function addFertility(c, st, actual) {
  const p = S.data.profile;
  const L = Math.min(17, Math.max(10, +p.lutealLength || 14));
  let ov = addDays(c.nextStart, -L);
  let src = c.kind === 'past' ? 'Calculated from this logged cycle' : 'Predicted from your average cycle';
  c.confirmed = false;
  if (actual) {
    c.sig = signals(c.start, c.boundary);
    if (c.sig.shift) { ov = addDays(c.sig.shift, -1); src = 'Confirmed by your temperature (BBT) rise'; c.confirmed = true; }
    else if (c.sig.opk) { ov = addDays(c.sig.opk, 1); src = 'Based on your positive ovulation test'; }
  }
  // ovulation can never be inside the first few days of a cycle
  if (diff(ov, c.start) < 7) ov = addDays(c.start, 7);
  c.ov = ov;
  c.ovSource = src;
  c.fStart = addDays(ov, -5);
  c.fEnd = addDays(ov, 1);
  c.pStart = addDays(ov, -2);
  if (c.kind !== 'past' && st.irregular && !c.confirmed && !(c.sig && c.sig.opk)) {
    c.fStart = minD(c.fStart, addDays(c.start, Math.max(7, st.min - L - 5)));
    c.fEnd = maxD(c.fEnd, addDays(c.start, st.max - L + 1));
    c.wide = true;
  }
  const per = S.data.periods.find((x) => x.start === c.start);
  c.pEnd = per && isDate(per.end) && per.end >= c.start ? per.end : addDays(c.start, Math.max(1, +p.periodLength || 5) - 1);
}

function buildEngine() {
  const st = cycleStats();
  const t = today();
  const cycles = [];
  st.starts.forEach((start, i) => {
    const next = st.starts[i + 1];
    let c;
    if (next) {
      c = { start, nextStart: next, boundary: next, length: diff(next, start), kind: 'past' };
    } else {
      const expected = addDays(start, st.avg);
      const late = t >= expected ? diff(t, expected) : -1; // 0 = due today
      c = { start, nextStart: expected, boundary: late >= 0 ? addDays(t, 1) : expected, length: st.avg, kind: 'current', late };
    }
    addFertility(c, st, true);
    cycles.push(c);
  });
  if (cycles.length) {
    let s = cycles[cycles.length - 1].boundary;
    for (let k = 0; k < 8; k++) {
      const c = { start: s, nextStart: addDays(s, st.avg), boundary: addDays(s, st.avg), length: st.avg, kind: 'projected' };
      addFertility(c, st, false);
      cycles.push(c);
      s = c.boundary;
    }
  }
  return { st, cycles, current: cycles.find((c) => c.kind === 'current') || null };
}

function eng() { if (!ENG) ENG = buildEngine(); return ENG; }

/** level: period | low | high | peak | luteal */
function dayInfo(date) {
  const c = eng().cycles.find((x) => date >= x.start && date < x.boundary);
  if (!c) return null;
  const cd = diff(date, c.start) + 1;
  let level = 'low';
  if (date <= c.pEnd) level = 'period';
  else if (date >= c.pStart && date <= c.ov) level = 'peak';
  else if (date >= c.fStart && date <= c.fEnd) level = 'high';
  else if (date > c.fEnd) level = 'luteal';
  const d = S.data.days[date];
  if (d && c.kind !== 'projected' && level !== 'period' && !(c.confirmed && date > c.fEnd)) {
    if (d.mucus === 'eggwhite') level = 'peak';
    else if (d.mucus === 'watery' && level !== 'peak') level = 'high';
  }
  return { c, cd, level, isOv: date === c.ov };
}

function monthsTrying() {
  const s = S.data.profile.tryingSince;
  if (!isDate(s) || s > today()) return null;
  return Math.floor(diff(today(), s) / 30.44);
}

/* =========================================================
 * Content
 * ======================================================= */
const HABITS = {
  her: [
    ['h_folic', 'Folic acid / prenatal vitamin'],
    ['h_water', '8+ glasses of water'],
    ['h_move', '30 min movement (walk, yoga, swim)'],
    ['h_veg', '5 servings fruit & vegetables'],
    ['h_protein', 'Protein at every meal'],
    ['h_caffeine', 'Caffeine ≤ 200 mg, no alcohol'],
    ['h_sleep', '7–8 hours of sleep'],
  ],
  him: [
    ['m_vit', 'Multivitamin (zinc, selenium, folate)'],
    ['m_move', '30 min exercise'],
    ['m_veg', '5 servings fruit & vegetables'],
    ['m_nuts', 'Handful of walnuts / seeds'],
    ['m_noalc', 'No alcohol, no smoking/tobacco'],
    ['m_cool', 'Keep cool: no laptop on lap, no hot tubs/sauna'],
    ['m_sleep', '7–8 hours of sleep'],
  ],
};

const TIPS = [
  'Sex every 1–2 days during the fertile window gives the best odds — daily is fine too if it is not stressful.',
  'Sperm can survive up to 5 days, the egg only about 12–24 hours. That is why the days BEFORE ovulation matter most.',
  'Slippery, stretchy "egg-white" cervical mucus is one of the best signs that ovulation is close.',
  'Ovulation tests (OPKs) work best tested in the afternoon; a positive usually means ovulation in the next 12–36 hours.',
  'Take your basal body temperature (BBT) right after waking, before getting out of bed, at the same time every day.',
  'Many regular lubricants can slow sperm. If you need one, choose a "fertility-friendly" lubricant.',
  'Sperm take about 74 days to develop — healthy changes he makes today show up in about 3 months.',
  'Keep the testicles cool: avoid laptops on the lap, hot baths, saunas and very tight underwear.',
  'Folic acid is most important in the first weeks of pregnancy, often before you know you are pregnant — take it daily now.',
  'There is no need to lie with legs up afterwards — a few minutes of rest is plenty.',
  'Stress does not "cause" infertility, but it can make sex feel like a chore. Keep date nights that are not about timing.',
  'At 35+, it is recommended to see a fertility specialist after 6 months of well-timed trying without success.',
  'Smoking (including second-hand) lowers fertility for both partners. Quitting is one of the best things you can do.',
  'Being at a healthy weight improves ovulation and sperm quality — even 5–10% weight loss helps if overweight.',
  'Moderate exercise helps fertility; very intense training that disrupts periods can hurt it.',
  'Iron + vitamin C together: add lemon to dal or have amla/guava with iron-rich meals for better absorption.',
  'Limit caffeine to about 200 mg a day — roughly one mug of brewed coffee or 2–3 cups of tea.',
  'Ask your doctor about thalassemia carrier screening — it is a simple blood test and important in South Asian families.',
  'Gum health matters — get a dental check-up before pregnancy.',
  'Celebrate small wins together. You are a team in this journey. 💞',
];

const CHECKLIST = [
  ['Her', [
    ['c_gyn', 'Pre-conception check-up with a gynaecologist'],
    ['c_folic', 'Started folic acid (at least 1–3 months before trying)'],
    ['c_blood', 'Blood tests: CBC/haemoglobin, thyroid (TSH), blood sugar (HbA1c), vitamin D & B12'],
    ['c_rubella', 'Rubella / MMR & chickenpox immunity checked (wait 1 month after these vaccines before trying)'],
    ['c_hepb', 'Hepatitis B status / vaccination'],
    ['c_pap', 'Cervical screening (Pap smear / HPV test) up to date'],
    ['c_amh', 'Discuss ovarian reserve tests (AMH / AFC ultrasound) with doctor — useful at 35+'],
    ['c_meds', 'Reviewed current medicines & supplements with doctor'],
    ['c_dental', 'Dental check-up'],
    ['c_weight', 'Healthy weight & blood pressure checked'],
  ]],
  ['Him', [
    ['m_check', 'General health check-up (BP, sugar, thyroid if needed)'],
    ['m_meds', 'Reviewed medicines (avoid testosterone / bodybuilding supplements)'],
    ['m_smoke', 'Stopped smoking / tobacco and cut alcohol'],
    ['m_semen', 'Semen analysis (do it early if trying > 6 months, or sooner if any concerns)'],
  ]],
  ['Together', [
    ['t_blood', 'Know both blood groups (Rh factor) '],
    ['t_thal', 'Thalassemia carrier screening (HbA2 / Hb electrophoresis)'],
    ['t_sti', 'STI screening (HIV, hepatitis, syphilis)'],
    ['t_genetic', 'Family medical history discussed; genetic counselling if any conditions run in family'],
    ['t_insurance', 'Health insurance: check maternity cover & waiting periods'],
    ['t_doctor', 'Shortlisted obstetrician & hospital'],
    ['t_budget', 'Basic baby budget & savings plan'],
    ['t_leave', 'Know your maternity / paternity leave policies'],
  ]],
];

const MUCUS = [['', '—'], ['dry', 'Dry / none'], ['sticky', 'Sticky'], ['creamy', 'Creamy / lotion-like'], ['watery', 'Watery (fertile)'], ['eggwhite', 'Egg-white, stretchy (most fertile)']];
const OPK = [['', 'Not tested'], ['negative', 'Negative'], ['positive', 'Positive (LH surge)'], ['peak', 'Peak / smiley']];
const TEST = [['', 'Not taken'], ['negative', 'Negative'], ['positive', 'Positive 🎉']];
const MOODS = [['', '—'], ['great', '😄 Great'], ['good', '🙂 Good'], ['ok', '😐 Okay'], ['low', '😔 Low'], ['stressed', '😣 Stressed']];
const SYMPTOMS = ['Cramps', 'Spotting', 'Bloating', 'Breast tenderness', 'Headache', 'Fatigue', 'Nausea', 'Acne', 'Back pain', 'Ovulation pain'];

/* =========================================================
 * Auth screens
 * ======================================================= */
let failCount = 0;
let lockUntil = 0;

function renderAuth(msg) {
  document.body.classList.add('locked');
  if (!window.crypto || !crypto.subtle) {
    app.innerHTML = `<div class="auth"><div class="card"><h1>Our Baby Plan</h1>
      <p class="err">This browser can't encrypt data here. Open the app over https:// (e.g. GitHub Pages) or as a local file in a modern browser.</p></div></div>`;
    return;
  }
  const vault = loadVault();
  if (!vault) return renderSetup();
  app.innerHTML = `
  <div class="auth"><form class="card" id="unlockForm" autocomplete="off">
    <div style="font-size:2rem">🔒</div>
    <h1>Our Baby Plan</h1>
    <p class="muted">Your private journal is locked.</p>
    ${msg ? `<p class="note info">${esc(msg)}</p>` : ''}
    <label for="pw">Password</label>
    <input id="pw" type="password" autocomplete="current-password" required autofocus>
    <p class="err" id="err"></p>
    <button class="btn primary block" type="submit" id="unlockBtn">Unlock</button>
    <p class="section"><button type="button" class="btn ghost small" id="forgot">Forgot password?</button></p>
  </form></div>`;
  const form = document.getElementById('unlockForm');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = document.getElementById('err');
    const btn = document.getElementById('unlockBtn');
    if (Date.now() < lockUntil) { err.textContent = `Too many attempts. Try again in ${Math.ceil((lockUntil - Date.now()) / 1000)}s.`; return; }
    btn.disabled = true; btn.textContent = 'Unlocking…'; err.textContent = '';
    try {
      const sess = await openVault(loadVault(), document.getElementById('pw').value);
      sess.data = normalise(sess.data);
      S = sess; failCount = 0; lastActivity = Date.now();
      view = 'today'; journalDate = today(); calMonth = today().slice(0, 7);
      render();
    } catch {
      failCount++;
      if (failCount >= 5) { lockUntil = Date.now() + 30000 * (failCount - 4); }
      err.textContent = 'Wrong password.';
      btn.disabled = false; btn.textContent = 'Unlock';
      document.getElementById('pw').select();
    }
  });
  document.getElementById('forgot').addEventListener('click', () => {
    const ok = prompt('Your data is encrypted with your password and cannot be recovered without it.\n\nIf you have a backup file you can restore it after resetting.\n\nType DELETE to erase this journal and start over:');
    if (ok === 'DELETE') { localStorage.removeItem(VAULT_KEY); renderSetup(); toast('Journal erased'); }
  });
}

function renderSetup() {
  app.innerHTML = `
  <div class="auth"><form class="card" id="setupForm" autocomplete="off">
    <div style="font-size:2rem">👶💞</div>
    <h1>Our Baby Plan</h1>
    <p class="muted">A private journal to time your tries, track signs and build healthy habits together.</p>
    <div class="fields">
      <div><label for="herName">Her name</label><input id="herName" maxlength="40" placeholder="Wife"></div>
      <div><label for="hisName">His name</label><input id="hisName" maxlength="40" placeholder="Manish"></div>
      <div><label for="herAge">Her age</label><input id="herAge" type="number" min="18" max="55" value="36"></div>
      <div><label for="hisAge">His age</label><input id="hisAge" type="number" min="18" max="70" value="35"></div>
      <div><label for="lastPeriod">First day of last period</label><input id="lastPeriod" type="date" max="${today()}"></div>
      <div><label for="cycleLen">Usual cycle length (days)</label><input id="cycleLen" type="number" min="20" max="45" value="28"></div>
      <div class="full"><label for="pw1">Create a password</label><input id="pw1" type="password" minlength="8" autocomplete="new-password" required placeholder="At least 8 characters"></div>
      <div class="full"><label for="pw2">Confirm password</label><input id="pw2" type="password" minlength="8" autocomplete="new-password" required></div>
    </div>
    <p class="note section">🔐 Your journal is encrypted with this password and stored only on this device. <b>There is no password reset</b> — if you forget it, the data can't be recovered. Keep regular backups (Settings → Backup).</p>
    <p class="err" id="err"></p>
    <button class="btn primary block" type="submit" id="createBtn">Create our private journal</button>
    <p class="section"><label for="importFile" class="btn ghost small block" style="margin:0">Restore from a backup file instead</label>
    <input id="importFile" type="file" accept="application/json,.json" class="sr"></p>
  </form></div>`;
  document.getElementById('setupForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const v = (id) => document.getElementById(id).value.trim();
    const err = document.getElementById('err');
    const pw1 = document.getElementById('pw1').value, pw2 = document.getElementById('pw2').value;
    if (pw1.length < 8) { err.textContent = 'Password must be at least 8 characters.'; return; }
    if (pw1 !== pw2) { err.textContent = 'Passwords do not match.'; return; }
    const btn = document.getElementById('createBtn'); btn.disabled = true; btn.textContent = 'Encrypting…';
    const data = defaultData();
    Object.assign(data.profile, {
      herName: v('herName'), hisName: v('hisName'),
      herAge: +v('herAge') || 36, hisAge: +v('hisAge') || 35,
      cycleLength: Math.min(45, Math.max(20, +v('cycleLen') || 28)),
      tryingSince: today(),
    });
    if (isDate(v('lastPeriod'))) data.periods.push({ start: v('lastPeriod') });
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(pw1, salt, PBKDF2_ITER);
    S = { key, salt, iter: PBKDF2_ITER, data };
    await save();
    lastActivity = Date.now();
    render();
    toast('Your private journal is ready');
  });
  document.getElementById('importFile').addEventListener('change', importBackup);
}

function importBackup(e) {
  const f = e.target.files && e.target.files[0];
  if (!f) return;
  const r = new FileReader();
  r.onload = () => {
    try {
      const v = JSON.parse(r.result);
      if (!(v && v.app === 'our-baby-plan' && v.ct && v.salt && v.iv && v.iter)) throw new Error('bad');
      if (loadVault() && !confirm('Replace the journal on this device with the backup? Current data here will be overwritten.')) return;
      localStorage.setItem(VAULT_KEY, JSON.stringify(v));
      lock('Backup restored. Unlock it with the password that was used when the backup was made.');
    } catch { alert('That file is not a valid Our Baby Plan backup.'); }
  };
  r.readAsText(f);
}

/* =========================================================
 * Main shell
 * ======================================================= */
const TABS = [
  ['today', '🏠', 'Today'],
  ['calendar', '📅', 'Calendar'],
  ['journal', '📝', 'Journal'],
  ['plan', '🥗', 'Diet & Fitness'],
  ['checklist', '✅', 'Checklist'],
  ['settings', '⚙️', 'Settings'],
];

function render() {
  if (!S) return renderAuth();
  ENG = null;
  document.body.classList.remove('locked');
  const p = S.data.profile;
  const names = [p.hisName, p.herName].filter(Boolean).join(' & ');
  const body = { today: viewToday, calendar: viewCalendar, journal: viewJournal, plan: viewPlan, checklist: viewChecklist, settings: viewSettings }[view]();
  app.innerHTML = `
    <header class="topbar">
      <div class="brand"><span class="logo">👶</span><span>${names ? esc(names) : 'Our Baby Plan'}</span></div>
      <button class="btn small" data-act="lock" aria-label="Lock journal">🔒 Lock</button>
    </header>
    <nav class="nav" aria-label="Sections">
      ${TABS.map(([id, ic, label]) => `<button data-view="${id}" ${view === id ? 'aria-current="page"' : ''}><span class="ic" aria-hidden="true">${ic}</span>${label}</button>`).join('')}
    </nav>
    <main class="shell">${body}
      <p class="disclaimer">Predictions are estimates and are not medical advice or a form of contraception. Please consult your doctor for personal guidance.</p>
    </main>`;
  afterRender();
}

function go(v) { view = v; render(); window.scrollTo(0, 0); }

/* ---------- Today ---------- */
function viewToday() {
  const t = today();
  const p = S.data.profile;
  const E = eng();
  const her = p.herName || 'her';

  if (!E.current) {
    return `<div class="stack section">
      <div class="card">
        <h1>Let's get started</h1>
        <p>To predict your fertile days, log the <b>first day of ${esc(her)}'s most recent period</b> (first day of full flow).</p>
        <div class="row"><input type="date" id="firstPeriod" max="${t}" style="max-width:220px"><button class="btn primary" data-act="addFirstPeriod">Save</button></div>
        <p class="muted section">Tip: add 2–3 past period dates in Journal → Period log for more accurate predictions.</p>
      </div>
      ${habitsCard(t)}
      ${tipCard()}
    </div>`;
  }

  const info = dayInfo(t);
  const c = info.c;
  const st = E.st;
  const preg = c.sig && c.sig.preg;
  let hero;
  const untilWindow = diff(c.fStart, t);
  const nextC = E.cycles[E.cycles.indexOf(c) + 1];

  if (preg) {
    hero = { cls: 'lv-preg', pill: 'Positive test', big: 'Congratulations! 🎉', text: `You logged a positive pregnancy test on ${nice(preg)}. Book an appointment with your gynaecologist, keep taking folic acid / prenatal vitamins, avoid alcohol and smoking, and take it easy. 💞` };
  } else if (info.level === 'period') {
    hero = { cls: 'lv-period', pill: `Period · day ${info.cd}`, big: 'Period days', text: `Rest, stay hydrated and eat iron-rich foods (dal, spinach, beetroot, dates, eggs) with vitamin C. Fertile window expected <b>${nice(c.fStart)} – ${nice(c.fEnd)}</b>.` };
  } else if (info.level === 'peak') {
    const left = diff(c.ov, t);
    hero = {
      cls: 'lv-peak', pill: 'Peak fertility',
      big: info.isOv ? 'Ovulation day (est.) — try today 💞' : 'Best time to try — today 💞',
      text: info.isOv
        ? 'Today is your estimated ovulation day. Try today, and again tomorrow if you can.'
        : `These are the most fertile days. Try today and every day or every other day until ${nice(c.fEnd)}. Estimated ovulation in ${plural(Math.max(left, 0), 'day')}.`,
    };
  } else if (info.level === 'high') {
    hero = t < c.ov
      ? { cls: 'lv-high', pill: 'Fertile window open', big: 'Good day to try 💞', text: `Your fertile window is open. Try every 1–2 days. Peak days start ${nice(c.pStart)}.` }
      : { cls: 'lv-high', pill: 'Fertile (last day)', big: 'Last fertile day — try today', text: 'The egg can live 12–24 hours after ovulation, so today can still count.' };
  } else if (info.level === 'luteal') {
    const testDay = c.confirmed ? addDays(c.ov, 14) : c.nextStart;
    if (c.kind === 'current' && c.late > 0) {
      hero = { cls: 'lv-luteal', pill: `Period ${plural(c.late, 'day')} late`, big: 'Time for a pregnancy test 🤞', text: 'Take a home pregnancy test with first-morning urine. If negative and still no period in 3–4 days, test again or see your doctor. Log the result in the Journal.' };
    } else {
      const d = diff(testDay, t);
      hero = { cls: 'lv-luteal', pill: 'Two-week wait', big: d > 0 ? `Test in ${plural(d, 'day')}` : 'You can test today', text: `The fertile window has passed. If ${esc(her)}'s period hasn't come by <b>${nice(testDay)}</b>, take a home pregnancy test. Keep up the healthy habits and be gentle with each other.` };
    }
  } else {
    hero = { cls: 'lv-low', pill: 'Low fertility', big: untilWindow > 0 ? `Fertile window opens in ${plural(untilWindow, 'day')}` : 'Low fertility today', text: `Expected fertile window <b>${nice(c.fStart)} – ${nice(c.fEnd)}</b>. Use these days to focus on diet, exercise and rest. Start ovulation tests around ${nice(addDays(c.fStart, -1))}.` };
  }

  // which window to show: this cycle's, or the next one if it has passed
  const wc = t > c.fEnd && nextC ? nextC : c;
  const d = S.data.days[t] || {};
  const months = monthsTrying();
  const herAge = +p.herAge || 36;
  const limit = herAge >= 40 ? 0 : herAge >= 35 ? 6 : 12;

  return `<div class="stack section">
    <div class="hero ${hero.cls}">
      <span class="pill">${esc(hero.pill)}</span>
      <div class="big">${hero.big}</div>
      <p style="margin:0">${hero.text}</p>
    </div>

    <div class="stats">
      <div class="stat"><div class="k">Cycle day</div><div class="v">${info.cd}${c.kind === 'current' ? ` <small class="muted">of ~${st.avg}</small>` : ''}</div></div>
      <div class="stat"><div class="k">Ovulation ${c.confirmed ? '✓' : '(est.)'}</div><div class="v">${nice(c.ov)}</div></div>
      <div class="stat"><div class="k">Next period</div><div class="v">${c.kind === 'current' && c.late > 0 ? 'Late' : nice(c.nextStart)}</div></div>
      <div class="stat"><div class="k">Avg cycle</div><div class="v">${st.avg} days${st.lens.length ? '' : ' <small class="muted">(default)</small>'}</div></div>
    </div>
    <p class="muted" style="margin:-4px 0 0;font-size:.85rem">ℹ️ ${esc(c.ovSource)}.${st.irregular ? ' Cycles vary a lot, so the window has been widened — ovulation tests are especially helpful.' : ''}${!st.lens.length ? ' Log a few periods for more accurate predictions.' : ''}</p>

    <div class="card">
      <div class="row between"><h2 style="margin:0">💞 Best days to try ${wc !== c ? '(next cycle)' : ''}</h2><small class="muted">${nice(wc.fStart)} – ${nice(wc.fEnd)}</small></div>
      <p class="muted" style="font-size:.9rem">Have sex every 1–2 days across the window. ★ marks the peak days — if you can only choose a few, choose these. Tap a day to log.</p>
      <div class="window">${windowDays(wc)}</div>
    </div>

    <div class="card">
      <h2>Quick log for today</h2>
      <div class="row">
        <button class="btn ${d.sex ? 'on' : ''}" data-act="toggleSex">${d.sex ? '💞 Tried today ✓' : '💞 We tried today'}</button>
        <button class="btn ${d.opk === 'positive' || d.opk === 'peak' ? 'on' : ''}" data-act="opkPos">🧪 Ovulation test +</button>
        <button class="btn ${d.mucus === 'eggwhite' ? 'on' : ''}" data-act="eggwhite">💧 Egg-white mucus</button>
        <button class="btn" data-act="periodToday">🩸 Period started today</button>
        <button class="btn ghost" data-act="openJournal" data-date="${t}">📝 Full entry</button>
      </div>
    </div>

    ${habitsCard(t)}

    <div class="grid two">
      <div class="card">
        <h2>⏳ How long we've been trying</h2>
        ${months === null
          ? '<p class="muted">Set the date you started trying in Settings.</p>'
          : `<p><b>${months < 1 ? 'Less than a month' : plural(months, 'month')}</b> since ${nice(p.tryingSince)}.</p>
             ${limit === 0
               ? '<p class="note">At 40+, doctors recommend seeing a fertility specialist right away rather than waiting.</p>'
               : months >= limit
                 ? `<p class="note">Since ${esc(her)} is ${herAge}, doctors recommend seeing a <b>fertility specialist</b> after ${limit} months of well-timed trying. This is very common and many couples just need a little help — please book a consultation for you both (including a semen analysis).</p>`
                 : `<p class="muted">Most couples conceive within a year. Because ${esc(her)} is ${herAge}, see a fertility specialist if not pregnant after <b>${limit} months</b> (about ${nice(addDays(p.tryingSince, Math.round(limit * 30.44)))}), or sooner if periods are irregular or very painful.</p>`}`}
      </div>
      ${tipCard()}
    </div>
  </div>`;
}

function windowDays(c) {
  const t = today();
  let out = '';
  for (let d = c.fStart; d <= c.fEnd; d = addDays(d, 1)) {
    const peak = d >= c.pStart && d <= c.ov;
    const done = S.data.days[d] && S.data.days[d].sex;
    out += `<button class="wday ${peak ? 'peak' : ''} ${d === t ? 'today' : ''}" data-act="openJournal" data-date="${d}" aria-label="${niceLong(d)}${peak ? ', peak day' : ''}${done ? ', tried' : ''}">
      <div>${wd(d)}</div><div class="d">${parse(d).getDate()}</div><div class="t">${done ? '💞' : peak ? '★' : '·'}</div></button>`;
  }
  return out;
}

function habitsCard(date) {
  const p = S.data.profile;
  const h = (S.data.days[date] && S.data.days[date].habits) || {};
  const col = (who, title) => {
    const list = HABITS[who];
    const n = list.filter(([id]) => h[id]).length;
    return `<div>
      <div class="row between"><h3 style="margin:0">${esc(title)}</h3><small class="muted">${n}/${list.length}</small></div>
      <div class="progress" style="margin:6px 0 4px"><span style="width:${Math.round((n / list.length) * 100)}%"></span></div>
      ${list.map(([id, label]) => `<label class="check"><input type="checkbox" data-habit="${id}" data-date="${date}" ${h[id] ? 'checked' : ''}> ${esc(label)}</label>`).join('')}
    </div>`;
  };
  return `<div class="card"><h2>🌿 Healthy habits ${date === today() ? 'today' : nice(date)}</h2>
    <div class="habits">${col('her', p.herName ? `${p.herName}` : 'Her')}${col('him', p.hisName ? `${p.hisName}` : 'Him')}</div></div>`;
}

function tipCard() {
  const i = Math.floor(Date.now() / 864e5) % TIPS.length;
  return `<div class="card"><h2>💡 Tip of the day</h2><p>${esc(TIPS[i])}</p></div>`;
}

/* ---------- Calendar ---------- */
function viewCalendar() {
  const [y, m] = calMonth.split('-').map(Number);
  const first = new Date(y, m - 1, 1, 12);
  const daysIn = new Date(y, m, 0).getDate();
  const t = today();
  let cells = '';
  for (let i = 0; i < first.getDay(); i++) cells += '<div class="cell empty"></div>';
  for (let day = 1; day <= daysIn; day++) {
    const ds = `${y}-${pad(m)}-${pad(day)}`;
    const info = S.data.periods.length ? dayInfo(ds) : null;
    const d = S.data.days[ds] || {};
    const marks = [d.sex ? '💞' : '', d.opk === 'positive' || d.opk === 'peak' ? '🧪' : '', d.bbt ? '🌡' : '', d.test === 'positive' ? '🎉' : ''].join('');
    const cls = ['cell', info ? `lv-${info.level}` : '', info && info.c.kind === 'projected' ? 'proj' : '', ds === t ? 'today' : ''].join(' ');
    const label = `${niceLong(ds)}${info ? `, ${info.level === 'low' ? 'low fertility' : info.level}` : ''}${info && info.isOv ? ', ovulation' : ''}${d.sex ? ', tried' : ''}`;
    cells += `<button class="${cls}" data-act="openJournal" data-date="${ds}" aria-label="${esc(label)}">
      ${info && info.isOv ? '<span class="ovdot" aria-hidden="true">⭐</span>' : ''}<span>${day}</span><span class="marks">${marks}</span></button>`;
  }
  const title = first.toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
  const dows = Array.from({ length: 7 }, (_, i) => new Date(2023, 0, 1 + i).toLocaleDateString(undefined, { weekday: 'narrow' }));
  return `<div class="stack section">
    <div class="card">
      <div class="row between">
        <button class="btn small" data-act="calPrev" aria-label="Previous month">‹</button>
        <h2 style="margin:0">${esc(title)}</h2>
        <button class="btn small" data-act="calNext" aria-label="Next month">›</button>
      </div>
      <div class="row" style="justify-content:center;margin:8px 0"><button class="btn ghost small" data-act="calToday">Today</button></div>
      <div class="cal">${dows.map((d) => `<div class="dow">${d}</div>`).join('')}${cells}</div>
      <div class="legend section">
        <span style="--sw:var(--period-soft)">Period</span>
        <span style="--sw:var(--high-soft)">Fertile</span>
        <span style="--sw:var(--peak-soft)">Peak (best days)</span>
        <span style="--sw:var(--luteal-soft)">Two-week wait</span>
        <span style="--sw:transparent;border:1px dashed var(--muted);border-radius:4px;padding:0 4px">Predicted</span>
      </div>
      <p class="muted" style="font-size:.85rem;margin-top:8px">⭐ ovulation · 💞 tried · 🧪 positive ovulation test · 🌡 temperature logged · 🎉 positive pregnancy test. Tap any day to open its journal entry.</p>
    </div>
    ${cycleHistoryCard()}
  </div>`;
}

function cycleHistoryCard() {
  const past = eng().cycles.filter((c) => c.kind === 'past').slice(-6).reverse();
  if (!past.length) return '';
  return `<div class="card"><h2>Cycle history</h2><div class="table-wrap"><table>
    <thead><tr><th>Started</th><th>Length</th><th>Ovulation</th><th>Tries in window</th></tr></thead>
    <tbody>${past.map((c) => {
      let tries = 0;
      for (let d = c.fStart; d <= c.fEnd; d = addDays(d, 1)) if (S.data.days[d] && S.data.days[d].sex) tries++;
      return `<tr><td>${nice(c.start)}</td><td>${c.length} days</td><td>${nice(c.ov)}${c.confirmed ? ' ✓' : ''}</td><td>${tries}</td></tr>`;
    }).join('')}</tbody></table></div></div>`;
}

/* ---------- Journal ---------- */
function viewJournal() {
  const ds = journalDate;
  const d = S.data.days[ds] || {};
  const p = S.data.profile;
  const info = S.data.periods.length ? dayInfo(ds) : null;
  const opts = (list, val) => list.map(([v, l]) => `<option value="${v}" ${v === (val || '') ? 'selected' : ''}>${esc(l)}</option>`).join('');
  const isStart = S.data.periods.some((x) => x.start === ds);
  const unit = p.tempUnit === 'F' ? '°F' : '°C';

  return `<div class="stack section">
    <div class="card">
      <div class="row between">
        <button class="btn small" data-act="jPrev" aria-label="Previous day">‹</button>
        <div style="text-align:center"><h2 style="margin:0">${niceLong(ds)}</h2>
          ${info ? `<small class="muted">Cycle day ${info.cd} · ${info.level === 'low' ? 'low fertility' : info.level === 'luteal' ? 'two-week wait' : info.level === 'peak' ? 'peak fertility' : info.level === 'high' ? 'fertile' : 'period'}${info.isOv ? ' · ovulation (est.)' : ''}</small>` : ''}
        </div>
        <button class="btn small" data-act="jNext" aria-label="Next day">›</button>
      </div>
      <div class="row" style="justify-content:center;margin-top:8px">
        <input type="date" id="jDate" value="${ds}" style="max-width:200px" aria-label="Choose date">
      </div>
    </div>

    <form class="card" id="journalForm" autocomplete="off">
      <h2>${esc(p.herName || 'Her')}'s signs</h2>
      <div class="fields">
        <div><label for="bbt">Basal body temp (${unit})</label><input id="bbt" type="number" step="0.01" inputmode="decimal" value="${esc(d.bbt ?? '')}" placeholder="${p.tempUnit === 'F' ? '97.6' : '36.45'}"></div>
        <div><label for="mucus">Cervical mucus</label><select id="mucus">${opts(MUCUS, d.mucus)}</select></div>
        <div><label for="opk">Ovulation test (OPK)</label><select id="opk">${opts(OPK, d.opk)}</select></div>
        <div><label for="test">Pregnancy test</label><select id="test">${opts(TEST, d.test)}</select></div>
        <div><label for="mood">Mood</label><select id="mood">${opts(MOODS, d.mood)}</select></div>
        <div><label for="weight">Weight (kg, optional)</label><input id="weight" type="number" step="0.1" inputmode="decimal" value="${esc(d.weight ?? '')}"></div>
      </div>
      <label>Symptoms</label>
      <div class="chips">${SYMPTOMS.map((s) => `<label class="check"><input type="checkbox" name="sym" value="${esc(s)}" ${(d.symptoms || []).includes(s) ? 'checked' : ''}> ${esc(s)}</label>`).join('')}</div>

      <h2 class="section">Together</h2>
      <label class="check"><input type="checkbox" id="sex" ${d.sex ? 'checked' : ''}> 💞 We had intercourse</label>
      <div class="fields">
        <div class="full"><label for="herNotes">${esc(p.herName || 'Her')}'s notes</label><textarea id="herNotes" maxlength="4000">${esc(d.herNotes || '')}</textarea></div>
        <div class="full"><label for="hisNotes">${esc(p.hisName || 'His')} notes</label><textarea id="hisNotes" maxlength="4000">${esc(d.hisNotes || '')}</textarea></div>
      </div>
      <div class="row section">
        <button class="btn primary" type="submit">Save entry</button>
        ${isStart
          ? '<button type="button" class="btn" data-act="unmarkPeriod">Remove period start</button>'
          : '<button type="button" class="btn" data-act="markPeriod">🩸 Period started this day</button>'}
        <button type="button" class="btn" data-act="markPeriodEnd">Period ended this day</button>
      </div>
    </form>

    ${habitsCard(ds)}
    ${bbtChartCard(info ? info.c : eng().current)}
    ${periodLogCard()}
    ${recentEntriesCard()}
  </div>`;
}

function bbtChartCard(c) {
  if (!c || c.kind === 'projected' || !c.sig || c.sig.temps.length < 2) {
    return `<div class="card"><h2>🌡 Temperature chart</h2><p class="muted">Log your basal body temperature each morning (before getting up). After ovulation it rises by ~0.2–0.5 °C; once 3 higher readings are logged the app confirms ovulation and refines your predictions.</p></div>`;
  }
  const W = 600, H = 220, padL = 40, padR = 10, padT = 14, padB = 28;
  const temps = c.sig.temps;
  const days = Math.max(c.length, diff(temps[temps.length - 1].date, c.start) + 1, 20);
  const ts = temps.map((x) => x.t);
  const lo = Math.min(...ts) - 0.15, hi = Math.max(...ts) + 0.15;
  const X = (cd) => padL + ((cd - 1) / (days - 1)) * (W - padL - padR);
  const Y = (t) => padT + (1 - (t - lo) / (hi - lo)) * (H - padT - padB);
  const pts = temps.map((x) => [X(diff(x.date, c.start) + 1), Y(x.t)]);
  const fs = diff(c.fStart, c.start) + 1, fe = diff(c.fEnd, c.start) + 1, ov = diff(c.ov, c.start) + 1;
  let grid = '';
  const step = (hi - lo) > 1.2 ? 0.5 : 0.2;
  for (let v = Math.ceil(lo / step) * step; v <= hi; v += step) grid += `<line class="axis" x1="${padL}" x2="${W - padR}" y1="${Y(v)}" y2="${Y(v)}"/><text class="lbl" x="4" y="${Y(v) + 4}">${v.toFixed(1)}</text>`;
  for (let cd = 1; cd <= days; cd += 7) grid += `<text class="lbl" x="${X(cd) - 4}" y="${H - 8}">${cd}</text>`;
  return `<div class="card chart"><h2>🌡 Temperature chart — cycle from ${nice(c.start)}</h2>
    <svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Basal body temperature chart for this cycle">
      <rect class="fert" x="${X(fs)}" y="${padT}" width="${Math.max(2, X(fe) - X(fs))}" height="${H - padT - padB}" rx="4"/>
      ${grid}
      <line class="ov" x1="${X(ov)}" x2="${X(ov)}" y1="${padT}" y2="${H - padB}"/>
      ${c.sig.cover ? `<line class="cover" x1="${padL}" x2="${W - padR}" y1="${Y(c.sig.cover)}" y2="${Y(c.sig.cover)}"/>` : ''}
      <polyline class="line" points="${pts.map((p) => p.join(',')).join(' ')}"/>
      ${pts.map((p) => `<circle class="pt" cx="${p[0]}" cy="${p[1]}" r="3.5"/>`).join('')}
    </svg>
    <p class="muted" style="font-size:.85rem">X-axis: cycle day. Shaded = fertile window, vertical line = ovulation ${c.confirmed ? '(confirmed)' : '(estimated)'}${c.sig.cover ? ', dashed = coverline' : ''}.</p></div>`;
}

function periodLogCard() {
  const list = [...S.data.periods].sort((a, b) => (a.start < b.start ? 1 : -1));
  return `<div class="card"><h2>🩸 Period log</h2>
    <p class="muted" style="font-size:.9rem">Add the first day of each period. More history = better predictions.</p>
    <div class="row"><input type="date" id="newPeriod" max="${today()}" style="max-width:200px" aria-label="Period start date"><button class="btn" data-act="addPeriod">Add period</button></div>
    ${list.length ? `<ul class="list-plain section">${list.map((x, i) => {
      const prev = list[i + 1];
      return `<li class="row between"><span><b>${niceLong(x.start)}</b>${x.end ? ` → ${nice(x.end)}` : ''}${prev ? ` <span class="tag">${diff(x.start, prev.start)}-day cycle</span>` : ''}</span>
        <button class="btn small ghost" data-act="delPeriod" data-date="${x.start}" aria-label="Delete period starting ${nice(x.start)}">Delete</button></li>`;
    }).join('')}</ul>` : '<p class="muted section">No periods logged yet.</p>'}
  </div>`;
}

function recentEntriesCard() {
  const keys = Object.keys(S.data.days).filter((k) => {
    const d = S.data.days[k];
    return d.bbt || d.mucus || d.opk || d.sex || d.herNotes || d.hisNotes || d.mood || d.test || (d.symptoms && d.symptoms.length);
  }).sort().reverse().slice(0, 14);
  if (!keys.length) return '';
  return `<div class="card"><h2>Recent entries</h2><ul class="list-plain">${keys.map((k) => {
    const d = S.data.days[k];
    const bits = [d.sex ? '💞 tried' : '', d.bbt ? `🌡 ${esc(d.bbt)}°` : '', d.opk ? `🧪 OPK ${esc(d.opk)}` : '', d.mucus ? `💧 ${esc(d.mucus)}` : '', d.test ? `test ${esc(d.test)}` : '', d.mood ? esc((MOODS.find((m) => m[0] === d.mood) || ['', ''])[1]) : ''].filter(Boolean).join(' · ');
    const note = d.herNotes || d.hisNotes || '';
    return `<li><button class="btn ghost small" data-act="openJournal" data-date="${k}" style="padding:0;min-height:0;border:0;font-weight:700">${niceLong(k)}</button>
      <div style="font-size:.9rem">${bits || '<span class="muted">notes</span>'}</div>${note ? `<div class="muted" style="font-size:.88rem">${esc(note.slice(0, 140))}${note.length > 140 ? '…' : ''}</div>` : ''}</li>`;
  }).join('')}</ul></div>`;
}

/* ---------- Diet & Fitness plan ---------- */
function weeklyScore(prefix) {
  const ids = HABITS[prefix].map((h) => h[0]);
  let done = 0;
  for (let i = 0; i < 7; i++) {
    const h = (S.data.days[addDays(today(), -i)] || {}).habits || {};
    done += ids.filter((id) => h[id]).length;
  }
  return Math.round((done / (ids.length * 7)) * 100);
}

function viewPlan() {
  const p = S.data.profile;
  const her = esc(p.herName || 'Her');
  const him = esc(p.hisName || 'Him');
  const info = S.data.periods.length ? dayInfo(today()) : null;
  const phase = info ? info.level : null;
  const phaseTip = {
    period: ['Period phase', 'Gentle movement (walking, stretching, restorative yoga). Focus on iron: dal, rajma, spinach/palak, beetroot, dates, eggs or lean meat — with lemon/amla for vitamin C. Warm fluids and rest.'],
    low: ['Follicular phase', 'Energy usually rises — a great time for strength training and brisk cardio. Load up on vegetables, whole grains and protein. Start ovulation tests a day before the fertile window.'],
    high: ['Fertile window', 'Keep exercise moderate and enjoyable; prioritise sleep and connection. Stay well hydrated (helps cervical mucus). Have sex every 1–2 days.'],
    peak: ['Peak fertility', 'Most fertile days — try today. Keep things relaxed, hydrate well, avoid heavy drinking or extreme workouts for both of you.'],
    luteal: ['Two-week wait', 'Continue moderate exercise (walks, yoga, swimming) — no need to stop. Avoid alcohol, hot tubs and saunas, limit caffeine. Complex carbs, nuts and magnesium-rich foods can help mood and cravings.'],
  }[phase];

  return `<div class="stack section">
    ${phaseTip ? `<div class="hero lv-${phase}"><span class="pill">Right now</span><div class="big">${phaseTip[0]}</div><p style="margin:0">${phaseTip[1]}</p></div>` : ''}

    <div class="grid two">
      <div class="card"><h3>${her}'s habits this week</h3><div class="progress"><span style="width:${weeklyScore('her')}%"></span></div><p class="muted">${weeklyScore('her')}% of daily habits done in the last 7 days</p></div>
      <div class="card"><h3>${him}'s habits this week</h3><div class="progress"><span style="width:${weeklyScore('him')}%"></span></div><p class="muted">${weeklyScore('him')}% of daily habits done in the last 7 days</p></div>
    </div>

    <div class="card">
      <h2>Your situation at a glance</h2>
      <p>At ${esc(p.herAge)} and ${esc(p.hisAge)} you are in a very common age range for a first or next pregnancy. Fertility for women begins to decline gradually after 35, so two things matter most: <b>well-timed sex in the fertile window</b> and <b>good health for both of you</b> (about half of fertility issues involve the male partner).</p>
      <ul>
        <li>Start <b>folic acid now</b> (${her}) — ideally at least 1–3 months before conception.</li>
        <li>Give changes ~<b>3 months</b> — that's how long eggs mature and sperm develop.</li>
        <li>See a fertility specialist after <b>6 months</b> of trying without success (because ${her} is 35+), or sooner if cycles are irregular (&lt;21 or &gt;35 days), very painful, or there's a known condition (PCOS, thyroid, endometriosis, previous miscarriage).</li>
      </ul>
    </div>

    <h2 class="section">🥗 Diet</h2>
    <details open><summary>For ${her} — fertility-friendly eating</summary><div class="body">
      <p>A Mediterranean-style pattern is linked with better fertility: plenty of vegetables, fruit, whole grains, legumes, nuts, healthy oils and fish, with little processed food and sugar.</p>
      <div class="table-wrap"><table><thead><tr><th>Nutrient</th><th>Why</th><th>Good sources</th></tr></thead><tbody>
        <tr><td><b>Folate</b></td><td>Prevents neural-tube defects</td><td>Palak, methi, broccoli, dal, rajma, chana, oranges + folic acid tablet</td></tr>
        <tr><td><b>Iron</b></td><td>Prevents anaemia (very common)</td><td>Dal, spinach, beetroot, dates, jaggery, eggs, lean meat — with lemon/amla</td></tr>
        <tr><td><b>Protein</b></td><td>Egg quality & hormones</td><td>Paneer, curd, dal, sprouts, tofu, eggs, chicken, fish</td></tr>
        <tr><td><b>Omega-3</b></td><td>Hormone balance, baby's brain</td><td>Walnuts, flaxseed, chia, salmon/sardine/mackerel (low-mercury)</td></tr>
        <tr><td><b>Calcium & Vit D</b></td><td>Bones; low Vit D is common</td><td>Milk, curd, ragi, sesame; 15–20 min sunlight; test levels</td></tr>
        <tr><td><b>Iodine</b></td><td>Thyroid & baby's brain</td><td>Iodised salt, dairy, eggs</td></tr>
        <tr><td><b>Slow carbs & fibre</b></td><td>Steady blood sugar helps ovulation</td><td>Brown rice, millets (jowar, bajra, ragi), oats, whole-wheat roti</td></tr>
      </tbody></table></div>
      <h4 class="section">Limit or avoid</h4>
      <ul>
        <li>Alcohol and smoking — none while trying.</li>
        <li>Caffeine over 200 mg/day (≈1 mug coffee or 2–3 cups tea).</li>
        <li>High-mercury fish (shark, swordfish, king mackerel), raw/undercooked meat & eggs, unpasteurised milk/cheese.</li>
        <li>Sugary drinks, fried snacks, trans fats (vanaspati, bakery items), excess sweets.</li>
        <li>Herbal "fertility" remedies or high-dose vitamin A without your doctor's advice.</li>
      </ul>
    </div></details>

    <details><summary>For ${him} — healthy sperm</summary><div class="body">
      <p>Sperm quality responds well to lifestyle — and it takes about <b>3 months</b> to see the effect.</p>
      <div class="table-wrap"><table><thead><tr><th>Nutrient</th><th>Why</th><th>Good sources</th></tr></thead><tbody>
        <tr><td><b>Zinc</b></td><td>Sperm production & testosterone</td><td>Pumpkin seeds, chickpeas, cashews, eggs, curd, chicken</td></tr>
        <tr><td><b>Antioxidants (Vit C, E)</b></td><td>Protect sperm DNA</td><td>Amla, guava, citrus, almonds, sunflower seeds, colourful vegetables</td></tr>
        <tr><td><b>Lycopene</b></td><td>Sperm motility</td><td>Cooked tomatoes, watermelon, papaya</td></tr>
        <tr><td><b>Selenium</b></td><td>Sperm movement</td><td>Eggs, fish, sunflower seeds, mushrooms, whole grains</td></tr>
        <tr><td><b>Omega-3 & walnuts</b></td><td>Studies: a handful (~60–75 g) daily improved sperm</td><td>Walnuts, flaxseed, fish</td></tr>
        <tr><td><b>Folate</b></td><td>Healthy sperm DNA</td><td>Leafy greens, dal, sprouts</td></tr>
      </tbody></table></div>
      <h4 class="section">Avoid</h4>
      <ul>
        <li>Smoking, gutka/tobacco, cannabis; heavy or binge drinking.</li>
        <li>Testosterone, steroids or "muscle-gain" supplements — they can stop sperm production.</li>
        <li>Heat: laptop on lap, hot baths, sauna/steam, very tight underwear, long hours sitting — take breaks.</li>
        <li>Processed meats, fried food, sugary drinks; aim for a healthy waist size.</li>
      </ul>
    </div></details>

    <details><summary>7-day sample meal plan (vegetarian, with non-veg swaps)</summary><div class="body">
      <div class="table-wrap"><table><thead><tr><th>Day</th><th>Breakfast</th><th>Lunch</th><th>Snack</th><th>Dinner</th></tr></thead><tbody>
        <tr><td>Mon</td><td>Vegetable oats upma + curd</td><td>Brown rice, palak dal, salad</td><td>Walnuts + orange</td><td>2 jowar roti, paneer bhurji, sautéed veg</td></tr>
        <tr><td>Tue</td><td>Moong chilla with mint chutney</td><td>Rajma, jeera rice (half brown), cucumber raita</td><td>Roasted chana + buttermilk</td><td>Vegetable khichdi with ghee, beetroot salad <small class="muted">/ grilled fish</small></td></tr>
        <tr><td>Wed</td><td>2 eggs / besan chilla + whole-wheat toast</td><td>Roti, chole, kachumber salad</td><td>Guava or amla + pumpkin seeds</td><td>Millet pulao, dal, curd <small class="muted">/ chicken curry</small></td></tr>
        <tr><td>Thu</td><td>Ragi dosa + sambar</td><td>Lemon rice with peanuts, mixed veg, curd</td><td>Sprouts chaat with tomato & lemon</td><td>Roti, methi dal, bhindi, salad</td></tr>
        <tr><td>Fri</td><td>Poha with peas & peanuts + fruit</td><td>Roti, palak paneer, dal</td><td>Smoothie: banana, milk, flax, dates</td><td>Quinoa/daliya pulao, raita <small class="muted">/ egg curry</small></td></tr>
        <tr><td>Sat</td><td>Stuffed paratha (methi/gobi) + curd</td><td>Sambar rice, cabbage poriyal</td><td>Fruit bowl + almonds</td><td>Grilled paneer/tofu tikka, salad, roti <small class="muted">/ fish tikka</small></td></tr>
        <tr><td>Sun</td><td>Idli + sambar + coconut chutney</td><td>Family meal — enjoy! Add a salad</td><td>Coconut water + makhana</td><td>Light soup (tomato/lentil) + vegetable sandwich</td></tr>
      </tbody></table></div>
      <p class="muted">Portion guide: half the plate vegetables, a quarter protein, a quarter whole grains. Cook with mustard, groundnut or olive oil; a little ghee is fine.</p>
    </div></details>

    <details><summary>Supplements to discuss with your doctor</summary><div class="body">
      <p><b>${her}:</b> folic acid 400–800 mcg daily (doctors in India often prescribe more — follow their dose) or a prenatal vitamin with folate, iodine and vitamin D; iron only if low; omega-3 DHA optional.</p>
      <p><b>${him}:</b> a basic men's multivitamin with zinc, selenium, folate and vitamins C & E is reasonable. Avoid high-dose or testosterone-boosting products.</p>
      <p class="note">Always check with your doctor first, especially for thyroid, blood pressure, diabetes or any regular medicines.</p>
    </div></details>

    <h2 class="section">🏃 Exercise</h2>
    <details open><summary>Weekly plan for both of you</summary><div class="body">
      <p>Target: <b>150 minutes of moderate activity per week</b> (you can talk but not sing) plus <b>2 strength sessions</b>. Moderate is the sweet spot — extreme training can disturb ovulation and sperm.</p>
      <div class="table-wrap"><table><thead><tr><th>Day</th><th>${her}</th><th>${him}</th></tr></thead><tbody>
        <tr><td>Mon</td><td>30 min brisk walk</td><td>30 min brisk walk / jog</td></tr>
        <tr><td>Tue</td><td>Strength 30 min (squats, lunges, glute bridges, light weights)</td><td>Strength 40 min (full body)</td></tr>
        <tr><td>Wed</td><td>Yoga 30–40 min</td><td>Swim / cycle 30 min (take breaks if cycling long)</td></tr>
        <tr><td>Thu</td><td>30 min walk together after dinner 💞</td><td>30 min walk together after dinner 💞</td></tr>
        <tr><td>Fri</td><td>Strength 30 min + stretching</td><td>Strength 40 min</td></tr>
        <tr><td>Sat</td><td>Dance / swim / hike 45 min</td><td>Sport (badminton, cricket, football) 45 min</td></tr>
        <tr><td>Sun</td><td>Rest + 10 min breathing / meditation</td><td>Rest + 10 min breathing / meditation</td></tr>
      </tbody></table></div>
      <h4 class="section">Good to know</h4>
      <ul>
        <li>Fertility-friendly yoga: Baddha Konasana (butterfly), Viparita Karani (legs up the wall), Setu Bandhasana (bridge), Balasana (child's pose), plus Anulom-Vilom breathing for stress.</li>
        <li>${her}: if periods become irregular or stop with heavy training, cut back intensity. Moderate exercise is safe in the two-week wait.</li>
        <li>${him}: avoid hot yoga; take standing breaks if you sit for long hours.</li>
        <li>Sleep 7–8 hours — poor sleep affects hormones for both partners.</li>
      </ul>
    </div></details>

    <details><summary>Healthy weight (BMI) check</summary><div class="body">
      <p>A BMI of about 18.5–23 (Asian guideline) is ideal for fertility. Even 5–10% weight loss can improve ovulation and sperm if overweight.</p>
      <div class="fields">
        <div><label for="bmiH">Height (cm)</label><input id="bmiH" type="number" inputmode="decimal"></div>
        <div><label for="bmiW">Weight (kg)</label><input id="bmiW" type="number" inputmode="decimal"></div>
      </div>
      <p id="bmiOut" class="section muted">Enter height and weight.</p>
    </div></details>

    <h2 class="section">💞 Timing & relationship</h2>
    <details><summary>How to get the timing right</summary><div class="body">
      <ul>
        <li>The fertile window is the <b>5 days before ovulation plus ovulation day</b>. The 2–3 days before ovulation are the best.</li>
        <li>Have sex every 1–2 days during the window. Daily is fine; there's no benefit to "saving up" sperm for more than 2–3 days.</li>
        <li>Use three signs together: this app's prediction, <b>ovulation tests</b> (start a day before the window, test in the afternoon) and <b>egg-white cervical mucus</b>. Morning temperature confirms ovulation after the fact.</li>
        <li>Use a fertility-friendly lubricant if needed; avoid saliva and regular lubricants.</li>
        <li>Keep it loving, not mechanical — plan date nights, and talk openly if it starts feeling stressful.</li>
      </ul>
    </div></details>
  </div>`;
}

/* ---------- Checklist ---------- */
function viewChecklist() {
  const total = CHECKLIST.reduce((n, [, items]) => n + items.length, 0);
  const done = CHECKLIST.reduce((n, [, items]) => n + items.filter(([id]) => S.data.checklist[id]).length, 0);
  const p = S.data.profile;
  const who = { Her: p.herName || 'Her', Him: p.hisName || 'Him', Together: 'Together' };
  return `<div class="stack section">
    <div class="card"><h1>Pre-conception checklist</h1>
      <div class="progress"><span style="width:${Math.round((done / total) * 100)}%"></span></div>
      <p class="muted">${done} of ${total} done</p></div>
    ${CHECKLIST.map(([group, items]) => `<div class="card"><h2>${esc(who[group])}</h2>
      ${items.map(([id, label]) => `<label class="check"><input type="checkbox" data-check="${id}" ${S.data.checklist[id] ? 'checked' : ''}> ${esc(label)}</label>`).join('')}</div>`).join('')}
  </div>`;
}

/* ---------- Settings ---------- */
function viewSettings() {
  const p = S.data.profile;
  return `<div class="stack section">
    <form class="card" id="profileForm" autocomplete="off">
      <h2>Profile & cycle</h2>
      <div class="fields">
        <div><label for="sHer">Her name</label><input id="sHer" maxlength="40" value="${esc(p.herName)}"></div>
        <div><label for="sHis">His name</label><input id="sHis" maxlength="40" value="${esc(p.hisName)}"></div>
        <div><label for="sHerAge">Her age</label><input id="sHerAge" type="number" min="18" max="55" value="${esc(p.herAge)}"></div>
        <div><label for="sHisAge">His age</label><input id="sHisAge" type="number" min="18" max="70" value="${esc(p.hisAge)}"></div>
        <div><label for="sTry">Started trying on</label><input id="sTry" type="date" max="${today()}" value="${esc(p.tryingSince)}"></div>
        <div><label for="sCycle">Usual cycle length (used until 2+ periods are logged)</label><input id="sCycle" type="number" min="20" max="45" value="${esc(p.cycleLength)}"></div>
        <div><label for="sPeriod">Period length (days)</label><input id="sPeriod" type="number" min="2" max="10" value="${esc(p.periodLength)}"></div>
        <div><label for="sLuteal">Luteal phase (days after ovulation)</label><input id="sLuteal" type="number" min="10" max="17" value="${esc(p.lutealLength)}"></div>
        <div><label for="sUnit">Temperature unit</label><select id="sUnit"><option value="C" ${p.tempUnit === 'C' ? 'selected' : ''}>°C</option><option value="F" ${p.tempUnit === 'F' ? 'selected' : ''}>°F</option></select></div>
        <div><label for="sLock">Auto-lock after</label><select id="sLock">${[1, 2, 5, 10, 30].map((m) => `<option value="${m}" ${+p.autoLock === m ? 'selected' : ''}>${m} min idle</option>`).join('')}</select></div>
      </div>
      <p class="muted section" style="font-size:.85rem">Luteal phase is usually 12–16 days; keep 14 unless your temperature charts or doctor show otherwise.</p>
      <button class="btn primary" type="submit">Save</button>
    </form>

    <form class="card" id="pwForm" autocomplete="off">
      <h2>🔐 Change password</h2>
      <label for="pwOld">Current password</label><input id="pwOld" type="password" autocomplete="current-password" required>
      <label for="pwNew">New password</label><input id="pwNew" type="password" minlength="8" autocomplete="new-password" required>
      <label for="pwNew2">Confirm new password</label><input id="pwNew2" type="password" minlength="8" autocomplete="new-password" required>
      <p class="err" id="pwErr"></p>
      <button class="btn primary" type="submit">Change password</button>
    </form>

    <div class="card">
      <h2>💾 Backup & move to another phone</h2>
      <p class="muted">The backup file is encrypted with your current password, so it's safe to keep in your email or cloud drive. To use the journal on another device, open the app there and choose "Restore from a backup file".</p>
      <div class="row">
        <button class="btn" data-act="export">Download encrypted backup</button>
        <label for="importFile2" class="btn" style="margin:0">Restore backup…</label>
        <input id="importFile2" type="file" accept="application/json,.json" class="sr">
      </div>
    </div>

    <div class="card">
      <h2>Privacy</h2>
      <ul>
        <li>Your data never leaves this device — the app has no server and blocks all network connections.</li>
        <li>Everything is encrypted (AES-256) with your password; it is never stored.</li>
        <li>The journal locks automatically after ${esc(p.autoLock)} min of inactivity. Tap 🔒 Lock when you put the phone down.</li>
        <li>Clearing browser data for this site deletes the journal — keep backups.</li>
      </ul>
      <button class="btn danger" data-act="wipe">Delete all data on this device</button>
    </div>
  </div>`;
}

/* =========================================================
 * Events
 * ======================================================= */
function entry(date) {
  if (!S.data.days[date]) S.data.days[date] = {};
  return S.data.days[date];
}

function addPeriodStart(date) {
  if (!isDate(date) || date > today()) { toast('Choose a valid date'); return false; }
  if (S.data.periods.some((x) => x.start === date)) { toast('Already logged'); return false; }
  const near = S.data.periods.find((x) => Math.abs(diff(x.start, date)) < 10);
  if (near && !confirm(`There's already a period logged on ${nice(near.start)}. Add ${nice(date)} as a separate period anyway?`)) return false;
  S.data.periods.push({ start: date });
  S.data.periods.sort((a, b) => (a.start < b.start ? -1 : 1));
  return true;
}

function afterRender() {
  const jd = document.getElementById('jDate');
  if (jd) jd.addEventListener('change', () => { if (isDate(jd.value)) { journalDate = jd.value; render(); } });

  const jf = document.getElementById('journalForm');
  if (jf) jf.addEventListener('submit', (e) => {
    e.preventDefault();
    const d = entry(journalDate);
    const val = (id) => document.getElementById(id).value.trim();
    d.bbt = val('bbt'); d.mucus = val('mucus'); d.opk = val('opk'); d.test = val('test'); d.mood = val('mood'); d.weight = val('weight');
    d.symptoms = [...jf.querySelectorAll('input[name=sym]:checked')].map((x) => x.value);
    d.sex = document.getElementById('sex').checked;
    d.herNotes = document.getElementById('herNotes').value; d.hisNotes = document.getElementById('hisNotes').value;
    save(); render(); toast(d.test === 'positive' ? 'Saved — congratulations! 🎉' : 'Entry saved');
  });

  const pf = document.getElementById('profileForm');
  if (pf) pf.addEventListener('submit', (e) => {
    e.preventDefault();
    const v = (id) => document.getElementById(id).value.trim();
    const clamp = (x, a, b, def) => Math.min(b, Math.max(a, +x || def));
    Object.assign(S.data.profile, {
      herName: v('sHer'), hisName: v('sHis'),
      herAge: clamp(v('sHerAge'), 18, 55, 36), hisAge: clamp(v('sHisAge'), 18, 70, 35),
      tryingSince: isDate(v('sTry')) ? v('sTry') : '',
      cycleLength: clamp(v('sCycle'), 20, 45, 28), periodLength: clamp(v('sPeriod'), 2, 10, 5),
      lutealLength: clamp(v('sLuteal'), 10, 17, 14), tempUnit: v('sUnit') === 'F' ? 'F' : 'C', autoLock: +v('sLock') || 5,
    });
    save(); render(); toast('Settings saved');
  });

  const pw = document.getElementById('pwForm');
  if (pw) pw.addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = document.getElementById('pwErr');
    const a = document.getElementById('pwOld').value, b = document.getElementById('pwNew').value, c = document.getElementById('pwNew2').value;
    if (b.length < 8) { err.textContent = 'New password must be at least 8 characters.'; return; }
    if (b !== c) { err.textContent = 'New passwords do not match.'; return; }
    try { await saveChain; await openVault(loadVault(), a); } catch { err.textContent = 'Current password is wrong.'; return; }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    S.key = await deriveKey(b, salt, PBKDF2_ITER); S.salt = salt; S.iter = PBKDF2_ITER;
    await save(); pw.reset(); err.textContent = ''; toast('Password changed');
  });

  const imp = document.getElementById('importFile2');
  if (imp) imp.addEventListener('change', importBackup);

  const bh = document.getElementById('bmiH'), bw = document.getElementById('bmiW');
  if (bh && bw) {
    const upd = () => {
      const h = +bh.value / 100, w = +bw.value, out = document.getElementById('bmiOut');
      if (!(h > 1 && w > 25)) { out.textContent = 'Enter height and weight.'; return; }
      const bmi = w / (h * h);
      const cat = bmi < 18.5 ? 'underweight — aim to gain a little with nutritious food' : bmi < 23 ? 'healthy range 👍' : bmi < 25 ? 'slightly above the Asian healthy range — small changes help' : bmi < 30 ? 'overweight — 5–10% weight loss can improve fertility' : 'obese range — weight loss can significantly improve fertility; ask your doctor for support';
      const lo = (18.5 * h * h).toFixed(0), hi = (23 * h * h).toFixed(0);
      out.textContent = `BMI ${bmi.toFixed(1)}: ${cat}. Healthy weight for this height: about ${lo}–${hi} kg.`;
    };
    bh.addEventListener('input', upd); bw.addEventListener('input', upd);
  }
}

app.addEventListener('change', (e) => {
  const el = e.target;
  if (!S) return;
  if (el.dataset.habit) {
    const d = entry(el.dataset.date);
    d.habits = d.habits || {};
    if (el.checked) d.habits[el.dataset.habit] = true; else delete d.habits[el.dataset.habit];
    save();
    const card = el.closest('.card');
    if (card) card.outerHTML = habitsCard(el.dataset.date);
  } else if (el.dataset.check) {
    if (el.checked) S.data.checklist[el.dataset.check] = true; else delete S.data.checklist[el.dataset.check];
    save(); render();
  }
});

app.addEventListener('click', async (e) => {
  const navBtn = e.target.closest('[data-view]');
  if (navBtn && S) { go(navBtn.dataset.view); return; }
  const b = e.target.closest('[data-act]');
  if (!b || !S) return;
  const act = b.dataset.act;
  const t = today();
  switch (act) {
    case 'lock': lock('Locked.'); break;
    case 'addFirstPeriod': {
      const v = document.getElementById('firstPeriod').value;
      if (addPeriodStart(v)) { save(); render(); toast('Saved — predictions are ready'); }
      break;
    }
    case 'toggleSex': { const d = entry(t); d.sex = !d.sex; save(); render(); toast(d.sex ? 'Logged 💞' : 'Removed'); break; }
    case 'opkPos': { const d = entry(t); d.opk = d.opk === 'positive' ? '' : 'positive'; save(); render(); toast(d.opk ? 'Positive OPK — ovulation likely in 12–36 h. Try today & tomorrow!' : 'Removed'); break; }
    case 'eggwhite': { const d = entry(t); d.mucus = d.mucus === 'eggwhite' ? '' : 'eggwhite'; save(); render(); toast(d.mucus ? 'Logged — very fertile sign!' : 'Removed'); break; }
    case 'periodToday': if (addPeriodStart(t)) { save(); render(); toast('New cycle started'); } break;
    case 'openJournal': journalDate = b.dataset.date; go('journal'); break;
    case 'jPrev': journalDate = addDays(journalDate, -1); render(); break;
    case 'jNext': journalDate = addDays(journalDate, 1); render(); break;
    case 'markPeriod': if (addPeriodStart(journalDate)) { save(); render(); toast('Period start saved'); } break;
    case 'unmarkPeriod': S.data.periods = S.data.periods.filter((x) => x.start !== journalDate); save(); render(); toast('Removed'); break;
    case 'markPeriodEnd': {
      const p = [...S.data.periods].filter((x) => x.start <= journalDate).sort((a, b2) => (a.start < b2.start ? 1 : -1))[0];
      if (!p || diff(journalDate, p.start) > 12) { toast('Log the period start first'); break; }
      p.end = journalDate; save(); render(); toast('Period end saved');
      break;
    }
    case 'addPeriod': { const v = document.getElementById('newPeriod').value; if (addPeriodStart(v)) { save(); render(); toast('Period added'); } break; }
    case 'delPeriod': if (confirm(`Delete period starting ${nice(b.dataset.date)}?`)) { S.data.periods = S.data.periods.filter((x) => x.start !== b.dataset.date); save(); render(); } break;
    case 'calPrev': case 'calNext': {
      const [y, m] = calMonth.split('-').map(Number);
      const d = new Date(y, m - 1 + (act === 'calNext' ? 1 : -1), 1, 12);
      calMonth = iso(d).slice(0, 7); render(); break;
    }
    case 'calToday': calMonth = t.slice(0, 7); render(); break;
    case 'export': {
      await saveChain;
      const blob = new Blob([localStorage.getItem(VAULT_KEY)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = `our-baby-plan-backup-${t}.json`;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      toast('Encrypted backup downloaded');
      break;
    }
    case 'wipe':
      if (prompt('This permanently deletes the journal from this device.\nType DELETE to confirm:') === 'DELETE') {
        localStorage.removeItem(VAULT_KEY); S = null; renderSetup(); toast('All data deleted');
      }
      break;
    default: break;
  }
});

renderAuth();
