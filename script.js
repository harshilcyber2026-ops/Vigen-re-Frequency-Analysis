/* ═══════════════════════════════════════════════════════════════════
   FlagVault CTF — Vigenère Frequency Analysis · Challenge #C4
   ───────────────────────────────────────────────────────────────
   CHALLENGE SETUP
   ───────────────
   Key        : CRYPTO  (length 6)
   Ciphertext : see BUILT_IN_CT below
   Plaintext  : English paragraph about cryptography
                The flag appears literally in the plaintext:
                "THE FLAG IS FLAGVAULT V1GEN3R3 FR3QU3NCY 4N4LYS1S"

   FLAG: FlagVault{v1gen3r3_fr3qu3ncy_4n4lys1s}

   HOW THE TOOL WORKS
   ──────────────────
   1. Player loads the ciphertext (built-in or pasted)
   2. IC Analysis: computes IC for key lengths 1–20, plots bar chart
      → Key length 6 will show highest IC (≈ 0.065)
   3. Frequency grids: splits CT into 6 streams, shows top letters
      → Most frequent letter in each stream → subtract 'E' = key letter
   4. Key builder: player types key, live decrypts, flag highlighted
   ═══════════════════════════════════════════════════════════════════ */

'use strict';

/* ──────────────── Built-in ciphertext (stripped) ──────────────── */
const BUILT_IN_CT = "VYCPKHQWAGRDVFEGTDJPFPLTCJAXGOVVBWNACEQUHFVYMJLOPUQDYMGRPHYFQDRWXOPTGTGHERCHTFEZNWXFVFKDWSTECCVFAGRXHBCCEDKWVYKHMVGXMPEVCJYAPOAJZTXBVFFXWSKEDDKACKGDGTTFKEKMKEETRSUKFTOWIVLTKSEZNWXFYRQDGQGTMCLWFVPTWIPSPTTYCSJTTBFNYHDBQNLPLZGTFXYTTVGCWSEYGUYFCSJTYCTECPKZAKFGXSEVLINFKVQXMGVFMSTGCWMGMFGJQPZOKEQIVFAGRPGONPQXLPWKAWTFNVQQTPDRETTBFCYIXFHIGTWFKTFZTGKJIXIFQMCSMVCKCKXBVYCHMFQEETLHECYHLWERJRBDJVPHVOPWYAEHQTYGXTWCKPMVGDYIBQCCYCTZAJGHMVGBCNMCDICPDWPXYKBUGECGXQKGFTKZKVQXGHJVPTISVZRXHBQWRWXYGPGILSNWUWXBVYCHTAGBCNESVKCGXBEIWEMGVYCHTAGGJPBBVVVIESVKCGMVGICHNZVZQPEKCPQXWSPKGRTZVYGHVFGRRTLDCKRTKBUKFPMOUBGAESFRLPEMUKAPGSZGJDBHVYCXGRGOMUVCKEAXWSPTCBXOULPTLVQNJXDSNPGIBGVYYIMKQIYCWCOCWRACUVLAXHVVPHYFQDYIXLVRPTMVGJYBXWPVLVEWUYRWBGXRJJXVQMCGLOTFSCWNGIMEHWPKXTKCUZVUBJGWMGTJKXCCXFGVLRKMRKCSMSZKRWXJCCSTWFQGQRECUVPIHNGIMEHWPKXTKCVYPTXSKXFIUMVIWXGUFZDUXFGERZXMNVLVMVURLSLDNZRIBBIKFTVWRYCGMSZKGCMCIIMJIGYVAPGTKEBIASNVLVMVYYCGXHJVGCWSZIGHXGDRAZMCVYCTGUNZQWOONLCDGQGKFTDSACCCZHJZQZGCYECPVVRFQXMWQEZTVCOVQPLWOGJTVOGJYGVWRYCGTBFWPTJIGEANTBCCWHBGTVTTTZUVYRAYGPJTMHGIRWXAQJRRHAOFLAXHVVPXGSPXJXLVKJCHHHJVKDLHHICFNSPKJTMHGIGCXOEYEGHIRCGZXZATMGKSUGMCWGVFCIASHCYVBGHCYVOOWCRKZSPIDGJIPTWCEMUJYCWBQNWDNYPFUIASUVAGXHQWRWXJKXCCXFGTGEASTTMCZFCKSATHKFLHHBUFJKBBIKFXLQJRJAXBIVWDNVCMCSXAQEQIKOVVBBTGVVPNHTECYHLWERJRKMRKYCTZAJGHMSEYLXJIGJRWTHJRTTUSGEPTYWPVBDOSTTCCMITZCHHTORRWXACKGRTZFZQRHJGIW";

const WIN_KEY = "CRYPTO";
const FLAG    = "FlagVault{v1gen3r3_fr3qu3ncy_4n4lys1s}";

let cipherBytes = [];   // processed ciphertext (uppercase A-Z)
let currentKeyLen = 6;

/* ──────────────── utility ──────────────── */
function cleanCT(raw) {
  return raw.toUpperCase().replace(/[^A-Z]/g, '');
}

function updateStats(ct) {
  document.getElementById('ct-len').textContent  = ct.length;
  document.getElementById('ct-uniq').textContent = new Set(ct).size;
  const ic = calcIC(ct);
  document.getElementById('ct-ic').textContent   = ic.toFixed(4);
}

/* ──────────────── Index of Coincidence ──────────────── */
function calcIC(text) {
  if (text.length < 2) return 0;
  const freq = new Array(26).fill(0);
  for (const c of text) freq[c.charCodeAt(0) - 65]++;
  const N = text.length;
  const num = freq.reduce((s, f) => s + f * (f - 1), 0);
  return num / (N * (N - 1));
}

function avgIC(ct, keyLen) {
  const streams = [];
  for (let i = 0; i < keyLen; i++) streams.push([]);
  for (let i = 0; i < ct.length; i++) streams[i % keyLen].push(ct[i]);
  const ics = streams.map(s => calcIC(s.join('')));
  return ics.reduce((a, b) => a + b, 0) / keyLen;
}

/* ──────────────── load ──────────────── */
function loadBuiltIn() {
  document.getElementById('ct-input').value = BUILT_IN_CT;
  cipherBytes = cleanCT(BUILT_IN_CT).split('');
  updateStats(BUILT_IN_CT);
  document.getElementById('btn-ic').disabled   = false;
  document.getElementById('btn-freq').disabled = false;
}

/* ──────────────── Step 2: IC Analysis ──────────────── */
function runICAnalysis() {
  const raw = document.getElementById('ct-input').value;
  const ct  = cleanCT(raw);
  if (ct.length < 50) { alert('Need at least 50 letters. Load the challenge file first.'); return; }
  cipherBytes = ct.split('');
  updateStats(ct);

  const maxL = 20;
  const ics  = [];
  for (let L = 1; L <= maxL; L++) ics.push({ L, ic: avgIC(ct, L) });

  const maxIC = Math.max(...ics.map(x => x.ic));

  // Render bar chart
  const chart = document.getElementById('ic-chart');
  chart.innerHTML = '';
  ics.forEach(({ L, ic }) => {
    const pct     = ic / maxIC;
    const isWin   = L === 6;
    const isNear  = !isWin && ic > 0.055;

    const wrap = document.createElement('div');
    wrap.className = 'ic-bar-wrap';

    const bar = document.createElement('div');
    bar.className = 'ic-bar' + (isWin ? ' winner' : isNear ? ' near' : '');
    bar.style.height = Math.max(pct * 100, 4) + 'px';
    bar.title = `L=${L}: IC=${ic.toFixed(4)}`;

    const lbl = document.createElement('div');
    lbl.className   = 'ic-bar-lbl';
    lbl.textContent = L;

    const val = document.createElement('div');
    val.className   = 'ic-bar-val';
    val.textContent = ic.toFixed(3);

    wrap.appendChild(bar);
    wrap.appendChild(lbl);
    wrap.appendChild(val);
    chart.appendChild(wrap);
  });

  // Result message
  const best = ics.reduce((a, b) => a.ic > b.ic ? a : b);
  document.getElementById('ic-result').textContent =
    `✓ Best key length: L = ${best.L}  (IC = ${best.ic.toFixed(4)})  →  Set key length to ${best.L} in Step 3`;

  document.getElementById('ic-chart-wrap').classList.remove('hidden');

  // Auto-set key length
  currentKeyLen = best.L;
  document.getElementById('kl-val').textContent = currentKeyLen;
}

/* ──────────────── Step 3: Frequency Analysis ──────────────── */
function changeKeyLen(d) {
  currentKeyLen = Math.max(1, Math.min(20, currentKeyLen + d));
  document.getElementById('kl-val').textContent = currentKeyLen;
}

function runFreqAnalysis() {
  const raw = document.getElementById('ct-input').value;
  const ct  = cleanCT(raw);
  if (ct.length < 20) { alert('Load the ciphertext first.'); return; }
  cipherBytes = ct.split('');

  const L = currentKeyLen;
  const streams = [];
  for (let i = 0; i < L; i++) streams.push([]);
  for (let i = 0; i < ct.length; i++) streams[i % L].push(ct[i]);

  const container = document.getElementById('freq-grids');
  container.innerHTML = '';

  streams.forEach((stream, pos) => {
    const freq = new Array(26).fill(0);
    stream.forEach(c => freq[c.charCodeAt(0) - 65]++);
    const total   = stream.length;
    const maxFreq = Math.max(...freq);

    // Find top letter → derive key letter
    const topIdx    = freq.indexOf(maxFreq);
    const topLetter = String.fromCharCode(topIdx + 65);
    const keyLetter = String.fromCharCode(((topIdx - 4 + 26) % 26) + 65);  // assuming top = 'E'

    const grid = document.createElement('div');
    grid.className = 'freq-grid';
    grid.innerHTML = `
      <div class="fg-title">POS ${pos + 1}</div>
      <div class="fg-top">Top: <strong>${topLetter}</strong> (${((freq[topIdx]/total)*100).toFixed(0)}%)</div>
      <div class="fg-key" title="Assuming top letter = 'E'">${keyLetter}</div>
    `;

    // Mini bar chart (top 6 letters)
    const sorted = freq.map((f, i) => ({ f, i })).sort((a, b) => b.f - a.f).slice(0, 6);
    const bars = document.createElement('div');
    bars.className = 'fg-bars';
    sorted.forEach((item, rank) => {
      const row = document.createElement('div');
      row.className = 'fg-bar-row';
      const w = (item.f / maxFreq) * 50;
      row.innerHTML = `
        <span class="fg-letter">${String.fromCharCode(item.i + 65)}</span>
        <div class="fg-bar-fill${rank === 0 ? ' top' : rank === 1 ? ' second' : ''}" style="width:${w}px"></div>
      `;
      bars.appendChild(row);
    });
    grid.appendChild(bars);
    container.appendChild(grid);
  });

  const suggestedKey = streams.map(stream => {
    const freq = new Array(26).fill(0);
    stream.forEach(c => freq[c.charCodeAt(0) - 65]++);
    const topIdx = freq.indexOf(Math.max(...freq));
    return String.fromCharCode(((topIdx - 4 + 26) % 26) + 65);
  }).join('');

  document.getElementById('freq-results').classList.remove('hidden');
  document.getElementById('key-input').value = suggestedKey;
  document.getElementById('key-hint').textContent = `Suggested key from frequency: ${suggestedKey}  (assumes most-frequent = E)`;
  liveDecrypt();
}

/* ──────────────── Step 4: Live Decrypt ──────────────── */
function vigenereDecrypt(ct, key) {
  if (!key) return '';
  const K = key.toUpperCase().replace(/[^A-Z]/g,'');
  if (!K.length) return '';
  let ki = 0;
  return ct.split('').map(c => {
    const shift = K.charCodeAt(ki % K.length) - 65;
    ki++;
    return String.fromCharCode((c.charCodeAt(0) - 65 - shift + 26) % 26 + 65);
  }).join('');
}

function liveDecrypt() {
  const key = document.getElementById('key-input').value.trim();
  const ct  = cipherBytes.join('');
  if (!ct || !key) return;

  const plain = vigenereDecrypt(ct, key);
  const win   = key.toUpperCase() === WIN_KEY;

  // Format with spaces every 5 chars
  let formatted = '';
  for (let i = 0; i < plain.length; i++) {
    if (i > 0 && i % 60 === 0) formatted += '\n';
    else if (i > 0 && i % 5 === 0) formatted += ' ';
    formatted += plain[i];
  }

  // Highlight flag if correct
  let display = formatted;
  if (win) {
    display = formatted.replace(/(FLAGVAULT)/g, '<span class="flag-hl">$1</span>');
  }

  const outEl = document.getElementById('decrypted-out');
  outEl.innerHTML = display;

  const badge = document.getElementById('do-badge');
  if (win) {
    badge.textContent = 'KEY CORRECT ✓';
    badge.className   = 'do-badge found';
    revealFlag();
  } else {
    badge.textContent = `Key: ${key.toUpperCase()}`;
    badge.className   = 'do-badge';
  }

  document.getElementById('decrypted-out-wrap').style.display = '';
}

/* ──────────────── flag reveal ──────────────── */
function revealFlag() {
  const wrap = document.getElementById('flag-reveal');
  if (!wrap.classList.contains('hidden')) return;
  document.getElementById('fr-val').textContent = FLAG;
  wrap.classList.remove('hidden');
  setTimeout(() => wrap.scrollIntoView({ behavior: 'smooth', block: 'center' }), 300);
}

function copyFlag() {
  const v = document.getElementById('fr-val').textContent;
  const t = document.getElementById('copy-toast');
  navigator.clipboard.writeText(v).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = v; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
  });
  t.classList.remove('hidden');
  setTimeout(() => t.classList.add('hidden'), 2000);
}

/* ──────────────── hints ──────────────── */
function toggleHint(n) {
  const b = document.getElementById(`h${n}b`);
  const t = document.getElementById(`h${n}t`);
  const h = b.classList.toggle('hidden');
  t.textContent = h ? '▼ Reveal' : '▲ Hide';
}

/* ──────────────── flag submit ──────────────── */
function submitFlag() {
  const v = document.getElementById('flag-input').value.trim();
  const r = document.getElementById('flag-result');
  if (`FlagVault{${v}}` === FLAG) {
    r.className = 'submit-result correct';
    r.innerHTML = '✓ &nbsp;Correct! Flag accepted. +300 pts';
    revealFlag();
  } else {
    r.className = 'submit-result incorrect';
    r.innerHTML = '✗ &nbsp;Incorrect flag. Keep trying.';
  }
}

/* ──────────────── textarea live stats ──────────────── */
document.addEventListener('DOMContentLoaded', () => {
  const ta = document.getElementById('ct-input');
  ta.addEventListener('input', () => {
    const ct = cleanCT(ta.value);
    cipherBytes = ct.split('');
    if (ct.length > 0) updateStats(ct);
  });

  document.getElementById('flag-input')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') submitFlag();
  });

  console.log('%c🔓 FlagVault CTF — Vigenère Frequency Analysis', 'font-size:14px;font-weight:bold;color:#00e8c8;');
  console.log('%c1. Load the file  2. Run IC Analysis (spike at L=6)  3. Freq Analysis  4. Key=CRYPTO', 'color:#b8cdd9;font-family:monospace;');
  console.log('%cFlag: FlagVault{v1gen3r3_fr3qu3ncy_4n4lys1s}', 'color:#f5a623;font-family:monospace;');
});
