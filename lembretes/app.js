// Crazy Buddy — Página Web de Lembretes Cifrados (Etapa 3)
// Usa WebCrypto nativo (AES-256-GCM) do Safari (iOS) e Chrome (Android), compatível com `crazybuddy-sync` em Rust.

const STORAGE_KEY = "crazybuddy_box_v1";
const TABLE = "crazybuddy_boxes";
const DEFAULT_SUPABASE_URL = "https://mmxdwcpdtkcdlthohhkg.supabase.co";
const DEFAULT_SUPABASE_ANON = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1teGR3Y3BkdGtjZGx0aG9oaGtnIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTUxMjA5NzgsImV4cCI6MjExMDY5Njk3OH0.DCYcMMuj0XAtp142tNf5IDy4P8gllWDm2Jy8jhiDsOg";

let creds = null;
let state = { version: 1, updatedAtMs: 0, reminders: [], deleted: {} };

const $ = (id) => document.getElementById(id);

function b64UrlToBytes(b64) {
  const pad = "=".repeat((4 - (b64.length % 4)) % 4);
  const std = (b64 + pad).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(std);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function bytesToB64Url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function newGuid() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

async function importAesKey(keyB64) {
  const raw = b64UrlToBytes(keyB64.trim());
  if (raw.byteLength !== 32) throw new Error("Chave inválida (precisa ter 256 bits).");
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encryptPayload(keyB64, obj) {
  const key = await importAesKey(keyB64);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(JSON.stringify(obj));
  const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, tagLength: 128 }, key, plain);
  return `v1.${bytesToB64Url(nonce)}.${bytesToB64Url(new Uint8Array(ctBuf))}`;
}

async function decryptPayload(keyB64, blob) {
  if (!blob || !blob.startsWith("v1.")) throw new Error("Formato cifrado inválido.");
  const parts = blob.slice(3).split(".");
  if (parts.length !== 2) throw new Error("Envelope cifrado incompleto.");
  const nonce = b64UrlToBytes(parts[0]);
  const ct = b64UrlToBytes(parts[1]);
  const key = await importAesKey(keyB64);
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, tagLength: 128 }, key, ct);
  const parsed = JSON.parse(new TextDecoder().decode(plainBuf));
  return {
    version: 1,
    updatedAtMs: parsed.updatedAtMs || 0,
    reminders: Array.isArray(parsed.reminders) ? parsed.reminders : [],
    deleted: parsed.deleted && typeof parsed.deleted === "object" ? parsed.deleted : {},
  };
}

function parseHashFragment(hashStr) {
  const clean = (hashStr || "").replace(/^#/, "").trim();
  if (!clean) return null;
  const params = new URLSearchParams(clean);
  const box = params.get("box")?.trim();
  const key = params.get("key")?.trim();
  if (!box || !key) return null;
  return {
    boxId: box,
    keyB64: key,
    supabaseUrl: (params.get("sb") || DEFAULT_SUPABASE_URL).trim().replace(/\/+$/, ""),
    supabaseAnon: (params.get("anon") || DEFAULT_SUPABASE_ANON).trim(),
  };
}

function loadCredentials() {
  const fromHash = parseHashFragment(location.hash);
  if (fromHash) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(fromHash));
    // Limpa o fragmento da barra de endereço após salvar no aparelho
    history.replaceState(null, "", location.pathname + location.search);
    return fromHash;
  }
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");
    if (saved?.boxId && saved?.keyB64) return saved;
  } catch (_) {}
  return null;
}

function showMsg(text, kind = "") {
  const bar = $("msg-bar");
  bar.textContent = text;
  bar.className = "msg " + kind;
  bar.hidden = !text;
}

function scheduleLabel(r) {
  if (r.mode === "interval") return `A cada ${r.value} min`;
  if (r.mode === "daily") return `Todo dia às ${r.value}`;
  if (r.mode === "date") return `Em ${r.value}${r.yearly ? " (anual)" : ""}`;
  return r.value;
}

function validateSchedule(mode, val) {
  const v = val.trim();
  if (mode === "interval") {
    const n = Number(v);
    return Number.isInteger(n) && n >= 1 && n <= 1440;
  }
  if (mode === "daily") {
    const parts = v.split(/[,;]/).map((s) => s.trim()).filter(Boolean);
    return parts.length > 0 && parts.every((p) => /^([01]?\d|2[0-3]):[0-5]\d$/.test(p));
  }
  if (mode === "date") {
    return /^\d{1,2}\/\d{1,2}\/\d{4}(\s+([01]?\d|2[0-3]):[0-5]\d)?$/.test(v);
  }
  return false;
}

async function pullFromSupabase() {
  if (!creds?.supabaseUrl || !creds?.supabaseAnon) return null;
  const url = `${creds.supabaseUrl}/rest/v1/${TABLE}?box_id=eq.${encodeURIComponent(creds.boxId)}&select=box_id,ciphertext,updated_at`;
  const res = await fetch(url, {
    headers: {
      apikey: creds.supabaseAnon,
      Authorization: `Bearer ${creds.supabaseAnon}`,
      Accept: "application/json",
    },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const rows = await res.json();
  if (!Array.isArray(rows) || rows.length === 0) return null;
  return decryptPayload(creds.keyB64, rows[0].ciphertext);
}

async function pushToSupabase() {
  if (!creds?.supabaseUrl || !creds?.supabaseAnon) {
    throw new Error("A URL e a chave pública do Supabase não vieram no QR. Preencha no painel do PC e gere o QR novamente.");
  }
  const ciphertext = await encryptPayload(creds.keyB64, state);
  const url = `${creds.supabaseUrl}/rest/v1/${TABLE}?on_conflict=box_id`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      apikey: creds.supabaseAnon,
      Authorization: `Bearer ${creds.supabaseAnon}`,
      "Content-Type": "application/json",
      Prefer: "resolution=merge-duplicates,return=minimal",
    },
    body: JSON.stringify({
      box_id: creds.boxId,
      ciphertext,
      updated_at: new Date().toISOString(),
    }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
}

function mergePayloads(localP, remoteP) {
  if (!remoteP) return localP;
  const deleted = { ...(remoteP.deleted || {}), ...(localP.deleted || {}) };
  for (const [id, t] of Object.entries(remoteP.deleted || {})) {
    deleted[id] = Math.max(t, localP.deleted?.[id] || 0);
  }
  const byId = new Map();
  for (const r of [...(remoteP.reminders || []), ...(localP.reminders || [])]) {
    if ((deleted[r.id] || 0) >= (r.updatedAtMs || 0)) continue;
    const prev = byId.get(r.id);
    if (!prev || (r.updatedAtMs || 0) >= (prev.updatedAtMs || 0)) {
      byId.set(r.id, r);
    }
  }
  return {
    version: 1,
    updatedAtMs: Math.max(localP.updatedAtMs || 0, remoteP.updatedAtMs || 0),
    reminders: [...byId.values()],
    deleted,
  };
}

async function syncAll(pushAfter = false) {
  try {
    $("status-sub").textContent = "Sincronizando caixa cifrada...";
    const remote = await pullFromSupabase();
    state = mergePayloads(state, remote);
    if (pushAfter) {
      state.updatedAtMs = Date.now();
      await pushToSupabase();
      showMsg("Sincronizado e cifrado com sucesso!", "ok");
    }
    $("status-sub").textContent = "Cifrado ponta a ponta (AES-256-GCM)";
  } catch (e) {
    $("status-sub").textContent = "Modo local (aguardando conexão)";
    showMsg(e.message || "Falha ao sincronizar com o Supabase.", "error");
  }
  renderList();
}

function renderList() {
  const list = $("rem-list");
  list.replaceChildren();
  $("rem-count").textContent = String(state.reminders.length);
  if (state.reminders.length === 0) {
    const empty = document.createElement("p");
    empty.className = "hint";
    empty.textContent = "Nenhum lembrete na caixa ainda. Crie o primeiro acima!";
    list.append(empty);
    return;
  }
  for (const r of state.reminders) {
    const row = document.createElement("div");
    row.className = "item" + (r.enabled ? "" : " off");

    const main = document.createElement("div");
    main.className = "item-main";

    const chk = document.createElement("input");
    chk.type = "checkbox";
    chk.checked = !!r.enabled;
    chk.onchange = () => {
      r.enabled = chk.checked;
      r.updatedAtMs = Date.now();
      r.origin = "mobile";
      syncAll(true);
    };

    const info = document.createElement("div");
    const title = document.createElement("div");
    title.className = "item-text";
    title.textContent = r.text;
    const sub = document.createElement("div");
    sub.className = "item-sub";
    sub.textContent = scheduleLabel(r);
    info.append(title, sub);
    main.append(chk, info);

    const btns = document.createElement("div");
    btns.className = "row";

    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "btn small ghost";
    editBtn.textContent = "Editar";
    editBtn.onclick = () => startEdit(r);

    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.className = "btn small danger";
    delBtn.textContent = "Apagar";
    delBtn.onclick = () => {
      const now = Date.now();
      state.deleted[r.id] = now;
      state.reminders = state.reminders.filter((x) => x.id !== r.id);
      syncAll(true);
    };

    btns.append(editBtn, delBtn);
    row.append(main, btns);
    list.append(row);
  }
}

function startEdit(r) {
  $("form-title").textContent = "Editar lembrete";
  $("rem-id").value = r.id;
  $("rem-text").value = r.text;
  $("rem-mode").value = r.mode;
  $("rem-val").value = r.value;
  $("rem-yearly").checked = !!r.yearly;
  $("btn-cancel").hidden = false;
  updateModeHints();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function resetForm() {
  $("form-title").textContent = "Novo lembrete";
  $("rem-id").value = "";
  $("rem-text").value = "";
  $("rem-mode").value = "daily";
  $("rem-val").value = "09:00";
  $("rem-yearly").checked = false;
  $("btn-cancel").hidden = true;
  updateModeHints();
}

function updateModeHints() {
  const m = $("rem-mode").value;
  $("rem-yearly-wrap").hidden = m !== "date";
  if (m === "daily") {
    $("rem-val-label").textContent = "Horários (ex.: 09:00, 18:30)";
    if (!$("rem-id").value) $("rem-val").value = "09:00";
  } else if (m === "interval") {
    $("rem-val-label").textContent = "Minutos (1 a 1440)";
    if (!$("rem-id").value) $("rem-val").value = "60";
  } else {
    $("rem-val-label").textContent = "Data e hora (ex.: 25/12/2026 09:00)";
    if (!$("rem-id").value) $("rem-val").value = "25/12/2026 09:00";
  }
}

function renderShell() {
  const paired = !!(creds?.boxId && creds?.keyB64);
  $("unpaired-card").hidden = paired;
  $("app-section").hidden = !paired;
  $("btn-sync").hidden = !paired;
  if (paired) {
    $("box-info").textContent = `Caixa pareada: ${creds.boxId}`;
    updateModeHints();
    syncAll(false);
  }
}

$("rem-mode").onchange = updateModeHints;
$("btn-cancel").onclick = () => { resetForm(); showMsg(""); };
$("btn-sync").onclick = () => syncAll(false);

$("btn-pair-url").onclick = () => {
  const raw = $("paste-url").value.trim();
  const idx = raw.indexOf("#");
  const parsed = parseHashFragment(idx >= 0 ? raw.slice(idx) : raw);
  if (!parsed) {
    alert("Link inválido. Copie o link completo gerado pelo botão 'Copiar link do QR' no painel do PC.");
    return;
  }
  creds = parsed;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(creds));
  renderShell();
};

$("btn-unpair").onclick = () => {
  if (!confirm("Desconectar este celular da caixa de recados?")) return;
  localStorage.removeItem(STORAGE_KEY);
  creds = null;
  state = { version: 1, updatedAtMs: 0, reminders: [], deleted: {} };
  renderShell();
};

$("rem-form").onsubmit = async (e) => {
  e.preventDefault();
  const id = $("rem-id").value.trim() || newGuid();
  const text = $("rem-text").value.trim();
  const mode = $("rem-mode").value;
  const value = $("rem-val").value.trim();
  const yearly = mode === "date" && $("rem-yearly").checked;

  if (!text) return showMsg("Digite a mensagem do lembrete.", "error");
  if (!validateSchedule(mode, value)) {
    return showMsg("Confira o formato do horário/data ou os minutos (1 a 1440).", "error");
  }

  const now = Date.now();
  const item = { id, text, mode, value, yearly, enabled: true, updatedAtMs: now, origin: "mobile" };
  delete state.deleted[id];
  const idx = state.reminders.findIndex((x) => x.id === id);
  if (idx >= 0) state.reminders[idx] = item;
  else state.reminders.push(item);

  resetForm();
  await syncAll(true);
};

creds = loadCredentials();
renderShell();
