const firebaseConfig = {
  apiKey: "AIzaSyCl8YDtZ9V0M0ZuPH5abt4aUBfSAFo77zY",
  authDomain: "msa-siracaltindag.firebaseapp.com",
  projectId: "msa-siracaltindag",
  storageBucket: "msa-siracaltindag.firebasestorage.app",
  messagingSenderId: "883902020685",
  appId: "1:883902020685:web:54f5d9e13b9134dfe0b004"
};

const ADMIN_UID = "Fr13u0sYFAhOybMNt2Dyr1UeqxA2";

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import {
  getAuth, setPersistence, browserLocalPersistence, createUserWithEmailAndPassword,
  signInWithEmailAndPassword, sendEmailVerification, sendPasswordResetEmail,
  updateProfile, signOut, onAuthStateChanged, EmailAuthProvider, reauthenticateWithCredential, updatePassword, deleteUser, updateEmail, verifyBeforeUpdateEmail
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import {
  getFirestore, doc, getDoc, getDocs, setDoc, updateDoc, addDoc, deleteDoc, collection, onSnapshot, serverTimestamp,
  query, where, orderBy, limit, writeBatch, arrayUnion, arrayRemove, increment
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
auth.languageCode = "tr";
const db = getFirestore(app);
const ready = setPersistence(auth, browserLocalPersistence).catch(() => {});

let emit = () => {}, unsub = null, regBusy = false, goneMsg = "";

const MAILDOM = "@kullanici.msa";
const slug = n => [...n.trim().toLowerCase()].map(c => /[a-z0-9_]/.test(c) ? c : "-" + c.codePointAt(0).toString(16)).join("");
const syncMap = u => { if (!u.email || isFake(u.email)) return; setDoc(doc(db, "usernames", slug(u.displayName || u.email.split("@")[0])), { uid: u.uid, email: u.email }).catch(() => {}); };
const toMail = id => id.includes("@") ? id : slug(id) + MAILDOM;
const isFake = e => (e || "").endsWith(MAILDOM);
const okMail = e => /^[^\s@]+@(gmail|hotmail)\.com$/i.test(e || "");

const ERR = {
  "auth/invalid-credential": "Kullanıcı adı/e-posta veya şifre hatalı.",
  "auth/wrong-password": "Kullanıcı adı/e-posta veya şifre hatalı.",
  "auth/user-not-found": "Kullanıcı adı/e-posta veya şifre hatalı.",
  "auth/invalid-email": "Geçerli bir kullanıcı adı veya e-posta gir.",
  "auth/email-already-in-use": "Bu kullanıcı adı veya e-posta zaten kayıtlı.",
  "auth/weak-password": "Şifre çok zayıf, en az 8 karakter kullan.",
  "auth/too-many-requests": "Çok fazla deneme yapıldı. Biraz bekleyip tekrar dene.",
  "auth/network-request-failed": "Bağlantı hatası. İnternetini kontrol et.",
  "auth/user-disabled": "Bu hesap devre dışı bırakılmış.",
  "auth/requires-recent-login": "Güvenlik için tekrar giriş yapıp dene.",
  "auth/operation-not-allowed": "E-posta değişikliği şu an kullanılamıyor (Firebase ayarı gerekli).",
  "auth/invalid-new-email": "Geçersiz e-posta.",
  "permission-denied": "Bu işlem için yetkin yok. (firestore.rules güncel mi?)"
};
const trError = e => ERR[e?.code] || "Hata: " + (e?.code || e?.message);

function validate(mode, v) {
  const e = {};
  if (mode !== "register" && !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v.email) && (mode === "reset" || !v.email || v.email.includes("@")))
    e.email = mode === "reset" ? "Şifre sıfırlamak için kayıtlı e-posta adresini gir (kullanıcı adı hesaplarında admine yaz)." : "Kullanıcı adı veya geçerli e-posta gir.";
  if (mode === "reset") return e;
  if (mode === "register") {
    if (!/^[\p{L}\p{N}_.]{3,20}$/u.test(v.username)) e.username = "3-20 karakter olmalı (harf, rakam, _ ve .).";
    if (!/^\S+( \S+)+$/.test(v.fullName)) e.fullName = "Ad ve soyadını gir.";
    if (v.remail && !okMail(v.remail)) e.remail = "Geçersiz e-posta.";
    if (v.password.length < 8) e.password = "Şifre en az 8 karakter olmalı.";
    if (v.password2 !== v.password) e.password2 = "Şifreler eşleşmiyor.";
    if (!v.kvkk) e.kvkk = "Devam etmek için Aydınlatma Metni onayı gerekli.";
  } else if (!v.password) e.password = "Şifreni gir.";
  return e;
}

async function resolve(u) {
  if (unsub) { unsub(); unsub = null; }
  if (!u) return emit({ screen: "auth" });
  if (!u.emailVerified && !isFake(u.email)) return emit({ screen: "verify", user: u });
  const ref = doc(db, "users", u.uid);
  if (u.uid === ADMIN_UID) {
    const s = await getDoc(ref), d = s.data();
    if (!s.exists() || d.status !== "approved" || d.role !== "admin") {
      await setDoc(ref, {
        username: u.displayName || u.email.split("@")[0], email: u.email,
        status: "approved", role: "admin",
        ...(s.exists() ? {} : { createdAt: serverTimestamp(), lastLogin: serverTimestamp() })
      }, { merge: true });
    }
  }
  if (auth.currentUser?.uid !== u.uid) return;
  let mapped = false;
  unsub = onSnapshot(ref, s => {
    if (!s.exists() && u.uid !== ADMIN_UID) { if (!s.metadata.fromCache) gone(u); return; }
    if (!mapped) { mapped = true; syncMap(u); }
    const d = s.exists() ? s.data() : null, st = d?.status || "pending";
    emit({ screen: st === "approved" ? "home" : st === "blocked" || st === "rejected" ? "blocked" : "pending", user: u, data: d });
  }, () => {});
}

async function gone(u) {
  if (unsub) { unsub(); unsub = null; }
  goneMsg = "Bu hesap admin tarafından silindi.";
  try { await deleteUser(u); } catch { await signOut(auth).catch(() => {}); }
}

async function startSession(cb) {
  emit = cb;
  await ready;
  onAuthStateChanged(auth, u => { if (!regBusy) resolve(u); });
}

async function signIn(email, password) {
  await ready;
  let ems = [toMail(email)];
  if (!email.includes("@")) { const m = await getDoc(doc(db, "usernames", slug(email))).catch(() => null); if (m?.exists() && m.data().email !== ems[0]) ems.unshift(m.data().email); }
  const byName = !email.includes("@") || isFake(email);
  let user;
  regBusy = true;
  try {
    for (let i = 0; i < ems.length; i++) {
      try { ({ user } = await signInWithEmailAndPassword(auth, ems[i], password)); break; }
      catch (x) { if (i === ems.length - 1 || !["auth/invalid-credential", "auth/user-not-found", "auth/wrong-password"].includes(x.code)) throw x; }
    }
    if (byName && user.uid !== ADMIN_UID) {
      const s = await getDoc(doc(db, "users", user.uid)).catch(() => null), cur = s?.exists() ? s.data().username : "";
      const typed = email.includes("@") ? email.split("@")[0] : slug(email);
      if (cur && slug(cur) !== typed) {
        await signOut(auth).catch(() => {});
        const x = new Error("old-username"); x.code = "auth/invalid-credential"; throw x;
      }
    }
  } finally { regBusy = false; }
  updateDoc(doc(db, "users", user.uid), { lastLogin: serverTimestamp() }).catch(() => {});
  await resolve(auth.currentUser);
}

async function signUp({ username, password, remail, fullName }) {
  await ready;
  const taken = await getDoc(doc(db, "usernames", slug(username))).catch(() => null);
  if (taken?.exists()) { const t = new Error("taken"); t.code = "auth/email-already-in-use"; throw t; }
  const email = slug(username) + MAILDOM;
  regBusy = true;
  try {
    const { user } = await createUserWithEmailAndPassword(auth, email, password);
    await updateProfile(user, { displayName: username });
    await setDoc(doc(db, "users", user.uid), { username, fullName, email: "", ...(remail ? { contactEmail: remail } : {}), status: "pending", createdAt: serverTimestamp(), lastLogin: null, kvkk: true, kvkkAt: serverTimestamp() });
    await addDoc(collection(db, "notifications"), { type: "new_user", uid: user.uid, username, createdAt: serverTimestamp(), read: false });
  } finally { regBusy = false; }
  await resolve(auth.currentUser);
}

const forgot = email => sendPasswordResetEmail(auth, email);
const resend = () => sendEmailVerification(auth.currentUser);
const logout = () => signOut(auth);

async function checkVerified() {
  await auth.currentUser.reload();
  if (!auth.currentUser.emailVerified) return false;
  await resolve(auth.currentUser);
  return true;
}


const $ = (s, r = document) => r.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const sleep = ms => new Promise(r => setTimeout(r, ms));

const stage = $("#stage"), home = $("#home"), splash = $("#splash");
const authView = $("#view-auth"), form = $("#form"), wrap = $("#submit-wrap");
const rs = $("#resend"), ck = $("#ck-wrap");
let mode = "login", busy = false, cur = null, cool = null;

const FIELDS = ["fullName", "username", "remail", "email", "password", "password2", "form", "verify"];
const setErr = (k, m = "", ok = false) => { const p = $("#e-" + k); p.textContent = m; p.classList.toggle("ok", ok); };
const clearErrs = () => FIELDS.forEach(k => setErr(k));
const shake = el => { el.classList.remove("shake"); void el.offsetWidth; el.classList.add("shake"); };
const vals = () => ({
  fullName: $("#fullName").value.trim().replace(/\s+/g, " "), username: $("#username").value.trim(), remail: $("#remail").value.trim().toLowerCase(), email: $("#email").value.trim(),
  password: $("#password").value, password2: $("#password2").value, kvkk: $("#kvkk").checked
});

function sync() {
  $$(".reg-only").forEach(e => e.inert = mode !== "register");
  $$(".login-only").forEach(e => e.inert = mode === "register");
}
sync();

$$(".tabs button").forEach(b => b.onclick = () => {
  mode = b.dataset.mode;
  $$(".tabs button").forEach(x => x.classList.toggle("on", x === b));
  authView.classList.toggle("reg", mode === "register");
  $(".lbl", wrap).textContent = mode === "login" ? "Giriş Yap" : "Kayıt Ol";
  $("#password").autocomplete = mode === "login" ? "current-password" : "new-password";
  clearErrs(); sync();
});

$$(".eye").forEach(b => b.onclick = () => {
  const i = b.previousElementSibling, show = i.type === "password";
  i.type = show ? "text" : "password";
  b.firstElementChild.firstElementChild.setAttribute("href", show ? "#i-eyeoff" : "#i-eye");
});

$$("#form input").forEach(i => i.oninput = () => { setErr(i.id); setErr("form"); });

form.onsubmit = async e => {
  e.preventDefault();
  if (busy) return;
  clearErrs();
  const v = vals(), er = validate(mode, v);
  if (Object.keys(er).length) { Object.entries(er).forEach(([k, m]) => setErr(k, m)); shake(wrap); return; }
  busy = true;
  wrap.classList.add("fast", "flash", "loading");
  await sleep(700);
  try {
    if (mode === "login") await signIn(v.email, v.password);
    else { await signUp(v); startCool(); }
  } catch (x) {
    const c = x.code || "";
    const k = c === "auth/email-already-in-use" || c === "auth/invalid-email" ? (mode === "register" ? "username" : "email") : c === "auth/weak-password" ? "password" : "form";
    setErr(k, trError(x));
    shake(wrap);
  }
  wrap.classList.remove("fast", "flash", "loading");
  busy = false;
};

$("#forgot").onclick = async () => {
  clearErrs();
  const email = $("#email").value.trim(), er = validate("reset", { email });
  if (er.email) return setErr("email", er.email);
  try { await forgot(email); setErr("form", "Sıfırlama bağlantısı e-postana gönderildi.", true); }
  catch (x) { setErr("form", trError(x)); }
};

function startCool() {
  clearInterval(cool);
  let n = 60;
  const t = () => {
    rs.disabled = n > 0;
    rs.textContent = n > 0 ? `Tekrar gönder (${n})` : "Tekrar gönder";
    if (n-- <= 0) clearInterval(cool);
  };
  t(); cool = setInterval(t, 1000);
}

rs.onclick = async () => {
  setErr("verify");
  try { await resend(); startCool(); setErr("verify", "Bağlantı tekrar gönderildi.", true); }
  catch (x) { setErr("verify", trError(x)); }
};

$("#checked").onclick = async () => {
  setErr("verify");
  ck.classList.add("loading");
  try { if (!await checkVerified()) setErr("verify", "E-posta henüz doğrulanmadı. Gelen kutunu ve spam klasörünü kontrol et."); }
  catch (x) { setErr("verify", trError(x)); }
  ck.classList.remove("loading");
};

$$("[data-logout]").forEach(b => b.onclick = async () => { logout(); });

function show(n) {
  if (n === cur) return;
  const first = cur === null, prev = cur;
  cur = n;
  const h = n === "home";
  stage.hidden = h; home.hidden = !h; document.body.classList.toggle("inhome", h);
  $$(".view").forEach(v => { const on = v.dataset.view === n; v.hidden = !on; v.classList.toggle("in", on); });
  if (n === "auth") { const el = $("#view-auth h1"); el.style.animation = "none"; void el.offsetWidth; el.style.animation = ""; }
  if (n === "auth" && !first && prev !== "auth") {
    form.reset(); $('[data-mode="login"]').click(); clearErrs();
    clearInterval(cool); rs.disabled = false; rs.textContent = "Tekrar gönder";
  }
}

const IC = {
  home: '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>',
  star: '<path d="M12 3l2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1L3.2 9.5l6.1-.9z"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-7 8-7s8 3 8 7"/>',
  code: '<path d="M8 8l-5 4 5 4M16 8l5 4-5 4M14 5l-4 14"/>',
  folder: '<path d="M3 6h6l2 3h10v11H3z"/>',
  note: '<path d="M5 3h14v18H5z"/><path d="M9 8h6M9 12h6M9 16h3"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',
  heart: '<path d="M12 20s-8-5-8-11a4.5 4.5 0 0 1 8-2.8A4.5 4.5 0 0 1 20 9c0 6-8 11-8 11z"/>',
  pin: '<path d="M9 3h6l-1 6 3 3H7l3-3zM12 12v9"/>',
  msg: '<path d="M4 5h16v11H9l-5 4z"/>',
  pen: '<path d="M4 20l1-4L16 5l3 3L8 19z"/>',
  trash: '<path d="M5 7h14M10 7V4h4v3M7 7l1 13h8l1-13"/>'
};
const ROUTES = {
  home: ["Ana Sayfa", "home"], favs: ["Favori Uygulamalar", "star"], profile: ["Profil", "user"],
  add: ["HTML Ekle", "code"], mine: ["HTML'lerim", "folder"], notes: ["Notlarım", "note"],
  settings: ["Ayarlar", "settings"], admin: ["Yönetim", "shield"]
};
const TABS = [["all", "Keşfet"], ["favs", "Favoriler"]];
const ST = { pending: "Bekliyor", approved: "Onaylı", blocked: "Engelli", rejected: "Reddedildi" };
const NT = {
  new_user: n => `${esc(n.username)} kayıt oldu`,
  html_pending: n => `${esc(n.username)} HTML ekledi: ${esc(n.detail)}`,
  access_request: n => `${esc(n.username)} açma isteği: ${esc(n.detail)}`,
  violation: n => `${esc(n.username)} ihlal yaptı: ${esc(n.detail)}`,
  chat: n => `${esc(n.username)} mesaj yazdı: ${esc(n.detail)}`
};
let ctx = {}, vio = false, gt = null;
const shell = $("#shell"), viewer = $("#viewer"), frame = $("#vf");
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = t => t?.toDate ? t.toDate().toLocaleString("tr-TR") : "—";
const ms = t => t?.toMillis ? t.toMillis() : Date.now();
const svg = n => `<svg class="ic" viewBox="0 0 24 24">${IC[n]}</svg>`;
const toast = m => { const t = document.createElement("div"); t.className = "toast"; t.textContent = m; document.body.append(t); setTimeout(() => t.remove(), 3200); };

const notify = (type, extra = {}) => addDoc(collection(db, "notifications"), {
  type, uid: auth.currentUser.uid, username: ctx.name || auth.currentUser.displayName || "", ...extra, createdAt: serverTimestamp(), read: false
}).catch(() => {});

const navItem = r => `<a href="#/${r}" data-r="${r}" title="${ROUTES[r][0]}" class="${r === "admin" ? "gold beam" : ""}">${svg(ROUTES[r][1])}<span class="lb">${ROUTES[r][0]}</span></a>`;
const empty = (b, m) => `<div class="emp"><svg class="ic" viewBox="0 0 24 24"><path d="M4 7l8-4 8 4v10l-8 4-8-4zM4 7l8 4 8-4M12 11v10"/></svg><p>${m || "Henüz içerik yok."}</p>${b ? '<a class="emb" href="#/add">İlk HTML\'ini paylaş</a>' : ""}</div>`;
const phd = t => `<p class="phd">${t}</p>`;

function hcard(h) {
  const S = ctx.S, n = S.likes.filter(l => l.htmlId === h.id).length, cc = Math.max(0, h.cc || 0);
  const xp = ctx.xid === h.id ? " xp" : "", lk = S.likes.some(l => l.htmlId === h.id && l.uid === ctx.uid), fv = S.prefs.favs.includes(h.id), pn = S.prefs.pins.includes(h.id);
  const own = h.by === ctx.uid;
  const B = (a, on, ic, x = "") => `<button data-a="${a}" data-id="${h.id}" class="${on ? "on" : ""}">${svg(ic)}${x}</button>`;
  return `<div class="card2${xp}" style="--cc:${cardColor(h)}" data-a="open" data-id="${h.id}"><div><div class="by">${avHtml(h.by, h.byName, "av xs")}<span class="n">${esc(h.byName || "")}${vb(h.by, "1.07em")}</span></div><b>${esc(h.title)}</b><small>${esc(h.desc)}</small>${h.status === "pending" ? '<em class="bd">Onay bekliyor · sadece sen görüyorsun</em>' : ""}</div><div class="acts">${B("like", lk, "heart", `<i>${n}</i>`)}${B("cm", 0, "msg", cc ? `<i>${cc}</i>` : "")}${B("fav", fv, "star")}${B("pin", pn, "pin")}${own ? B("edit", 0, "pen") : ctx.admin ? B("del", 0, "trash") : ""}</div><button type="button" class="openb" data-a="openh" data-id="${h.id}">Aç</button></div>`;
}
const grid = l => l.length ? `<div class="grid">${[...l].sort((a, b) => ctx.S.prefs.pins.includes(b.id) - ctx.S.prefs.pins.includes(a.id)).map(hcard).join("")}</div>` : empty(1);

function adminPage() {
  const S = ctx.S, at = ctx.at;
  const tabs = `<div class="htabs">${[["users", "Kullanıcılar"], ["pend", "Bekleyenler"], ["msgs", "Mesajlar"], ["data", "Veri"], ["trace", "İz çöz"], ["ann", "Duyuru"]].map(([k, t]) => `<button data-at="${k}" class="${k === at ? "on" : ""}">${t}</button>`).join("")}</div>`;
  if (at === "users") {
    const U = S.users.filter(u => u.id !== ADMIN_UID).sort((a, b) => (a.status === "pending" ? 0 : 1) - (b.status === "pending" ? 0 : 1) || (a.username || "").localeCompare(b.username || ""));
    const ub = u => {
      const B = (v, t) => `<button data-a="ust" data-id="${u.id}" data-v="${v}" data-n="${esc(u.username)}">${t}</button>`;
      const m = u.status === "pending" ? B("approved", "Onayla") + B("rejected", "Reddet") : u.status === "approved" ? B("blocked", "Engelle") : B("approved", "Engeli kaldır");
      return m + `<button data-a="trust" data-id="${u.id}" data-v="${u.trusted ? "" : "1"}" data-n="${esc(u.username)}">${u.trusted ? "Güvenilirliği kaldır" : "Güvenilir yap"}</button><button data-a="udel" data-id="${u.id}" data-n="${esc(u.username)}">Sil</button>`;
    };
    return tabs + (U.map(u => {
      const op = ctx.uxp === u.id, on = u.lastSeen?.toMillis && Date.now() - u.lastSeen.toMillis() < 3e5;
      const bd = `<em class="bd st-${u.status}">${ST[u.status] || u.status}</em>${u.selfDeleted ? ' <em class="bd st-blocked">hesabı sildi</em>' : ""}${u.violationAt && u.status === "pending" ? ' <em class="bd st-blocked">ihlal nedeniyle</em>' : ""}${on ? ' <em class="bd st-approved">çevrimiçi</em>' : ""}`;
      return `<div class="row2 ur" data-a="uxp" data-id="${u.id}"><div class="uh">${avHtml(u.id, u.username, "av sm")}<b>${esc(u.username)}${vb(u.id)}</b> ${bd}<span class="chev">${op ? "▲" : "▼"}</span></div>${op ? `<div class="ud"><small>${esc(u.contactEmail || (u.email && !isFake(u.email) ? u.email : "e-posta yok"))}${u.trusted ? " · güvenilir" : u.mailExempt ? " · e-posta muaf" : ""}</small><small>Son giriş: ${fmt(u.lastLogin)}</small><small>Son görülme: ${fmt(u.lastSeen)}</small><div class="btns ub">${ub(u)}</div></div>` : ""}</div>`;
    }).join("") || empty());
  }
  if (at === "data") {
    const du = ctx.du || "all", all = du === "all", D = ctx.dv;
    const nm = Object.fromEntries(S.users.map(u => [u.id, u.username || u.email]));
    const uo = `<option value="all"${all ? " selected" : ""}>Tümü</option>` + S.users.map(u => `<option value="${u.id}"${u.id === du ? " selected" : ""}>${esc(u.username || u.email)}</option>`).join("");
    const F = { fullName: "Ad Soyad", username: "Kullanıcı adı", contactEmail: "E-posta", bio: "Biyografi", photoURL: "Fotoğraf" };
    const ut = n => all && n ? ` <em class="bd st-approved">${esc(n)}</em>` : "", dl = x => x.deleted ? ' <em class="bd st-blocked">silindi</em>' : "";
    const notes = S.allNotes.filter(n => all || n.uid === du).sort((a, b) => ms(b.updatedAt) - ms(a.updatedAt));
    const htmls = S.allHtmls.filter(h => all || h.by === du).sort((a, b) => ms(b.createdAt) - ms(a.createdAt));
    const prof = D ? D.prof.map(p => `<div class="tick">✓ ${ut(p.u)}<b>${F[p.field] || esc(p.field)}</b>: ${esc(p.old) || "—"} → ${esc(p.new) || "—"}<small>${fmt(p.ts)}</small></div>`).join("") || empty() : '<p class="muted">Yükleniyor...</p>';
    const body = `<h3 class="sh">Profil geçmişi <button class="btn-ghost sm" data-a="pclr" type="button">Temizle</button></h3>${prof}<h3 class="sh">Notlar</h3>${notes.map(n => `<div class="row2"><div><b>${esc(n.title || "Başlıksız")}</b>${dl(n)}${ut(nm[n.uid])}<small class="nt">${esc(n.text)}</small><small>${fmt(n.updatedAt)}</small></div><div class="btns"><button data-a="ddel" data-k="notes" data-id="${n.id}">Sil</button></div></div>`).join("") || empty()}<h3 class="sh">HTML'ler</h3>${htmls.map(x => `<div class="row2"><div><b>${esc(x.title)}</b> <em class="bd st-${x.status}">${ST[x.status] || x.status}</em>${dl(x)}${ut(nm[x.by])}<small>${fmt(x.createdAt)}</small></div><div class="btns"><button data-a="dl" data-id="${x.id}" data-n="${esc(x.title)}">İndir</button><button data-a="ddel" data-k="htmls" data-id="${x.id}">Sil</button></div></div>`).join("") || empty()}`;
    return tabs + `<div class="lf"><select id="du">${uo}</select></div>` + body;
  }
  if (at === "trace") {
    return tabs + '<form class="addf" onsubmit="return false"><p class="muted">Sızan HTML\'i veya metni buraya yapıştır. Gizli iz ve filigran yazısı aranır.</p><textarea id="trin" placeholder="Yapıştır..." style="height:160px"></textarea><button class="btn2" type="button" data-a="trace"><span class="lbl">İzi Çöz</span></button></form><div id="trout"></div>';
  }
  if (at === "ann") {
    return tabs + `<form id="anf" class="addf"><textarea id="anx" maxlength="500" placeholder="Duyuru yaz..." style="height:100px"></textarea><button class="btn2" type="submit"><span class="lbl">Herkese Gönder</span><i class="spin"></i></button></form><h3 class="sh">Gönderilenler</h3>` + (S.ann.map(a => `<div class="row2"><div><small class="nt">${esc(a.text)}</small><small>${fmt(a.ts)}</small></div><div class="btns"><button data-a="andel" data-id="${a.id}">Sil</button></div></div>`).join("") || empty());
  }
  if (at === "msgs") {
    const C = [...S.chats].sort((a, b) => ms(b.updated) - ms(a.updated));
    const list = C.map(c => `<div class="row2${c.id === ctx.ct ? " sel" : ""}" data-a="ch" data-id="${c.id}"><div>${avHtml(c.id, c.name, "av sm")}<b>${esc(c.name)}</b>${c.adminUnread ? ` <em class="bd st-pending">${c.adminUnread} yeni</em>` : ""}<small>${esc(c.last)}</small></div><small>${fmt(c.updated)}</small></div>`).join("");
    const mu = '<option value="">Yeni mesaj: kullanıcı seç</option>' + S.users.filter(u => u.id !== ADMIN_UID && u.status === "approved").map(u => `<option value="${u.id}"${u.id === ctx.ct ? " selected" : ""}>${esc(u.username || u.email)}</option>`).join("");
    const cn = ctx.ct ? esc(S.users.find(u => u.id === ctx.ct)?.username || S.chats.find(c => c.id === ctx.ct)?.name || "") : "";
    const conv = ctx.ct ? `<h3 class="sh">${avHtml(ctx.ct, cn, "av sm")}${cn}</h3><div id="adl" class="chl">${ctx.cmsgs.map(m => bub(m, m.from === "admin")).join("")}</div><form id="adf" class="chf"><input id="adx" maxlength="500" placeholder="Cevap yaz..." autocomplete="off"><button class="ib" type="submit" aria-label="Gönder">➤</button></form><button class="btn-ghost sm" data-a="cdelall" type="button" style="margin-top:10px">Sohbeti tamamen sil</button>` : "";
    return tabs + `<div class="lf"><select id="mu">${mu}</select></div>` + (list || empty()) + conv;
  }
  if (at === "pend") {
    const hp = S.pend.map(h => `<div class="row2"><div><b>${esc(h.title)}</b><small>${esc(h.byName)} · ${esc(h.desc)}</small></div><div class="btns"><button data-a="dl" data-id="${h.id}" data-n="${esc(h.title)}">İndir</button><button data-a="hap" data-id="${h.id}">Onayla</button><button data-a="hrej" data-id="${h.id}">Reddet</button></div></div>`).join("");
    const rq = S.reqs.map(r => `<div class="row2"><div><b>${esc(r.name)}</b><small>${esc(r.title)}</small></div><div class="btns"><button data-a="acc" data-id="${r.uid}_${r.htmlId}" data-v="granted">İzin ver</button><button data-a="acc" data-id="${r.uid}_${r.htmlId}" data-v="denied">Reddet</button></div></div>`).join("");
    return tabs + `<h3 class="sh">HTML onayları</h3>${hp || empty()}<h3 class="sh">Açma istekleri</h3>${rq || empty()}`;
  }

  return tabs;
}

const needMail = () => !ctx.admin && !ctx.prof?.mailExempt && !okMail(ctx.prof?.contactEmail) && isFake(ctx.email);
function backfill() {
  try { if (localStorage.umap2) return; } catch {}
  const us = ctx.S.users.filter(u => u.email && !isFake(u.email) && u.username);
  if (!us.length) return;
  const w = writeBatch(db);
  us.forEach(u => w.set(doc(db, "usernames", slug(u.username)), { uid: u.id, email: u.email }));
  w.commit().then(() => { try { localStorage.umap2 = "1"; } catch {} }).catch(() => {});
}
const ids = v => v === "all" ? ctx.S.users.map(u => u.id) : [v];
async function delCol(q) {
  const s = await getDocs(q);
  for (let i = 0; i < s.docs.length; i += 400) { const w = writeBatch(db); s.docs.slice(i, i + 400).forEach(x => w.delete(x.ref)); await w.commit(); }
  return s.docs;
}
async function wipeHtml(id) {
  await delCol(query(collection(db, "comments"), where("htmlId", "==", id)));
  await delCol(query(collection(db, "likes"), where("htmlId", "==", id)));
  await delCol(query(collection(db, "access"), where("htmlId", "==", id)));
  await deleteDoc(doc(db, "htmlBodies", id)).catch(() => {});
  await deleteDoc(doc(db, "htmls", id));
}
async function wipeUser(id) {
  const u = ctx.S.users.find(x => x.id === id), col = n => collection(db, n);
  const hs = await getDocs(query(col("htmls"), where("by", "==", id)));
  for (const h of hs.docs) await wipeHtml(h.id);
  await delCol(query(col("htmlBodies"), where("by", "==", id)));
  await delCol(query(col("notes"), where("uid", "==", id)));
  await deleteDoc(doc(db, "profiles", id)).catch(() => {});
  const cs = await getDocs(query(col("comments"), where("uid", "==", id)));
  for (const c of cs.docs) await delCol(query(col("comments"), where("parent", "==", c.id)));
  await delCol(query(col("comments"), where("uid", "==", id)));
  await delCol(query(col("likes"), where("uid", "==", id)));
  await delCol(query(col("access"), where("uid", "==", id)));
  await delCol(query(col("notifications"), where("uid", "==", id)));
  await delCol(query(col("usernames"), where("uid", "==", id)));
  if (u?.username) await deleteDoc(doc(db, "usernames", slug(u.username))).catch(() => {});
  await delCol(collection(db, "chats", id, "msgs"));
  await delCol(collection(db, "profileHistory", id, "items"));
  await deleteDoc(doc(db, "chats", id)).catch(() => {});
  await deleteDoc(doc(db, "prefs", id)).catch(() => {});
  await deleteDoc(doc(db, "users", id));
}

const PAGES = {
  favs: () => { const l = ctx.S.htmls.filter(h => ctx.S.prefs.favs.includes(h.id)); return phd(l.length + " favori") + (l.length ? grid(l) : empty(0, "Henüz favori yok.")); },
  mine: () => phd(ctx.S.mine.length + " HTML") + grid(ctx.S.mine),
  add: () => `<form id="addf" class="addf"><input id="ht" placeholder="Başlık" maxlength="80"><input id="hd" placeholder="Açıklama" maxlength="200"><textarea id="hh" placeholder="HTML kodu"></textarea><p class="err" id="e-add"></p><button class="btn2" type="submit"><span class="lbl">${ctx.admin ? "Yayınla" : "Onaya Gönder"}</span><i class="spin"></i></button></form>`,
  notes: empty, settings: empty,
  profile: () => `<p><b>${esc(ctx.name)}</b></p><p class="muted">${esc(ctx.email)}</p>`,
  admin: adminPage
};

function render() {
  const keep = ["adx", "anx"].map(i => { const x = $("#" + i); return [i, x?.value, x && document.activeElement === x]; });
  const sl = $(".htabs")?.scrollLeft || 0;
  $("#content").innerHTML = PAGES[ctx.r]();
  keep.forEach(([i, v, f]) => { const n = $("#" + i); if (n) { if (v) n.value = v; if (f) n.focus(); } });
  const t = $(".htabs");
  if (t) {
    t.scrollLeft = sl;
    const on = t.querySelector(".on");
    if (on) { const l = on.offsetLeft, r = l + on.offsetWidth; if (l < t.scrollLeft) t.scrollLeft = l - 8; else if (r > t.scrollLeft + t.clientWidth) t.scrollLeft = r - t.clientWidth + 8; }
  }
  $("#adl")?.scrollTo(0, 1e9);
  xpRestore();
}
/* Kart genişletme: kart yerinde bir boşluk (xph) bırakıp diğer kartların üstüne biner, arkası bulanır */
function xpOff() {
  $$(".xph,.xbk").forEach(n => n.remove());
  $$(".card2.xp").forEach(c => { c.classList.remove("xp"); ["position", "left", "top", "width", "height", "zIndex", "transition", "overflow"].forEach(k => c.style[k] = ""); });
  ctx.xid = null;
}
function xpOn(c) {
  const g = c.parentElement, gr = g.getBoundingClientRect(), r = c.getBoundingClientRect(), cs = getComputedStyle(g);
  if (cs.position === "static") g.style.position = "relative";
  const pl = parseFloat(cs.paddingLeft) || 0, W = g.clientWidth - pl - (parseFloat(cs.paddingRight) || 0);
  const L = r.left - gr.left - (parseFloat(cs.borderLeftWidth) || 0), T = r.top - gr.top - (parseFloat(cs.borderTopWidth) || 0);
  const ph = document.createElement("div"); ph.className = "xph"; c.before(ph);
  const set = (el, l, t, w, h, m = 0) => Object.assign(el.style, { left: (l - m) + "px", top: (t - m) + "px", width: (w + 2 * m) + "px", height: (h + 2 * m) + "px" });
  c.classList.add("xp");
  Object.assign(c.style, { position: "absolute", zIndex: "30", transition: "none", overflow: "hidden" });
  set(c, pl, T, W, 0); c.style.height = "auto"; const H = c.offsetHeight;
  set(c, L, T, r.width, r.height);
  void c.offsetWidth;
  const tr = "left .3s var(--ease),top .3s var(--ease),width .3s var(--ease),height .3s var(--ease)";
  c.style.transition = tr;
  set(c, pl, T, W, H);
  ctx.xid = c.dataset.id;
  setTimeout(() => { if (c.classList.contains("xp")) { c.style.transition = "none"; c.style.height = "auto"; c.style.overflow = ""; } }, 340);
}
function xpRestore() {
  if (!ctx.xid) return;
  const c = $(`.card2[data-id="${ctx.xid}"]`);
  if (!c) { ctx.xid = null; return; }
  c.classList.remove("xp"); xpOn(c);
}
const rf = () => {
  if (ctx.r === "home" && $("#hg")) { $("#hg").innerHTML = homeGrid(); xpRestore(); return; }
  if (ctx.r === "notes" && $("#nl")) { $("#nl").innerHTML = notesList(); return; }
  if (["favs", "mine", "admin"].includes(ctx.r)) render();
};

function route() {
  if (!ctx.uid) return;
  let r = location.hash.replace("#/", "") || "home";
  if (!ROUTES[r] || (r === "admin" && !ctx.admin)) r = "home";
  if (r === "add") { if (location.hash !== "#/home") location.hash = "#/home"; openEditor(null); return; }
  ctx.r = r;
  $$("#nav a,#navb a").forEach(a => a.classList.toggle("on", a.dataset.r === r));
  $("#ptitle").textContent = ROUTES[r][0];
  const c = $("#content");
  c.classList.remove("in"); void c.offsetWidth; c.classList.add("in");
  render();
  shell.classList.remove("open");
  scrollTo(0, 0);
}

function notifRender() {
  const S = ctx.S, dot = $("#bell .dot");
  if (!ctx.admin) {
    const cu = S.chat?.userUnread || 0, seen = S.prefs.annSeen || 0, n = cu + S.ann.filter(a => ms(a.ts) > seen).length;
    dot.hidden = !n; dot.textContent = n;
    const it = (cu ? `<div class="nit un" data-a="openchat">Admin'den ${cu} yeni mesaj</div>` : "") + S.ann.map(a => `<div class="nit${ms(a.ts) > seen ? " un" : ""}">${esc(a.text)}<small>${fmt(a.ts)}</small></div>`).join("");
    $("#nlist").innerHTML = it || '<p class="muted">Henüz bildirim yok.</p>';
    return;
  }
  const N = S.notifs, u = N.filter(n => !n.read).length;
  dot.hidden = !u; dot.textContent = u; $("#nclr").hidden = !N.length; $("#nall").hidden = !N.some(n => !n.read);
  $("#nlist").innerHTML = N.length ? N.map(n => `<div class="nit${n.read ? "" : " un"} t-${n.type}" data-a="nread" data-id="${n.id}" data-k="${n.type}">${(NT[n.type] || (x => esc(x.type)))(n)}<small>${fmt(n.createdAt)}</small></div>`).join("") : '<p class="muted">Henüz bildirim yok.</p>';
}

async function loadProf() {
  const v = ctx.du || "all", nm = Object.fromEntries(ctx.S.users.map(u => [u.id, u.username || u.email]));
  ctx.dv = null;
  try {
    const ps = await Promise.all(ids(v).map(i => getDocs(query(collection(db, "profileHistory", i, "items"), orderBy("ts", "desc"), limit(100))).then(q => q.docs.map(d => ({ id: d.id, ...d.data(), u: nm[i] })))));
    if ((ctx.du || "all") !== v) return;
    ctx.dv = { prof: ps.flat().sort((a, b) => ms(b.ts) - ms(a.ts)).slice(0, 300) };
  } catch (x) { toast(trError(x)); ctx.dv = { prof: [] }; }
  if (ctx.r === "admin" && ctx.at === "data") render();
}

const bumpCc = (id, k) => { if (id && k) updateDoc(doc(db, "htmls", id), { cc: increment(k) }).catch(() => {}); };
async function recountCc() {
  try {
    const cs = await getDocs(collection(db, "comments")), cnt = {};
    cs.docs.forEach(d => { const x = d.data(); if (!x.deleted && x.htmlId) cnt[x.htmlId] = (cnt[x.htmlId] || 0) + 1; });
    const hs = await getDocs(collection(db, "htmls")), rows = hs.docs.filter(d => (d.data().cc || 0) !== (cnt[d.id] || 0));
    for (let i = 0; i < rows.length; i += 400) { const w = writeBatch(db); rows.slice(i, i + 400).forEach(d => w.update(d.ref, { cc: cnt[d.id] || 0 })); await w.commit(); }
  } catch {}
}
function startData() {
  const S = ctx.S, c = n => collection(db, n), map = s => s.docs.map(d => ({ id: d.id, ...d.data() }));
  const sub = (q, fn) => ctx.subs.push(onSnapshot(q, fn, () => {}));
  sub(query(c("htmls"), where("status", "==", "approved")), s => { S.htmls = map(s).filter(x => !x.deleted); rf(); });
  sub(query(c("htmls"), where("by", "==", ctx.uid)), s => { S.mine = map(s).filter(x => !x.deleted); rf(); });
  sub(c("likes"), s => { S.likes = map(s); rf(); });
  sub(c("profiles"), s => {
    S.profiles = Object.fromEntries(s.docs.map(d => [d.id, d.data()]));
    avatarUpd(); rf(); if (ctx.r === "profile") render();
    if (ctx.cm) cmRender(); if (!$("#chat").hidden) chatDraw();
  });
  sub(query(c("notes"), where("uid", "==", ctx.uid)), s => { S.notes = map(s); rf(); });
  sub(query(c("announcements"), orderBy("ts", "desc"), limit(20)), s => { S.ann = map(s); rf(); notifRender(); });
  sub(doc(db, "settings", "badges"), s => { S.badges = s.data()?.uids || []; rf(); if (ctx.r === "profile") render(); if (ctx.cm) cmRender(); });
  sub(doc(db, "prefs", ctx.uid), s => { S.prefs = { favs: [], pins: [], ...s.data() }; rf(); notifRender(); });
  sub(query(c("access"), where("uid", "==", ctx.uid)), s => { S.access = {}; s.docs.forEach(d => S.access[d.data().htmlId] = d.data().status); });
  if (!ctx.admin) sub(doc(db, "chats", ctx.uid), s => { S.chat = s.data() || {}; notifRender(); if (!$("#chat").hidden) chatDraw(); if (!$("#chat").hidden && S.chat.userUnread) setDoc(doc(db, "chats", ctx.uid), { userUnread: 0 }, { merge: true }).catch(() => {}); });
  if (ctx.admin) {
    sub(c("chats"), s => { S.chats = map(s); rf(); });
    sub(c("users"), s => { S.users = map(s); rf(); backfill(); });
    sub(c("notes"), s => { S.allNotes = map(s); rf(); });
    sub(c("htmls"), s => { S.allHtmls = map(s); rf(); });
    sub(query(c("htmls"), where("status", "==", "pending")), s => { S.pend = map(s).filter(x => !x.deleted); rf(); });
    sub(query(c("access"), where("status", "==", "requested")), s => { S.reqs = map(s); rf(); });
    sub(query(c("notifications"), orderBy("createdAt", "desc"), limit(30)), s => { S.notifs = map(s); notifRender(); });
    recountCc();
  }
}

function buildHome(user, data) {
  const name = data?.username || user.displayName || "";
  if (ctx.uid === user.uid) { ctx.name = name; ctx.prof = data || {}; $("#hname").textContent = name; avatarUpd(); return; }
  ctx = {
    uid: user.uid, admin: user.uid === ADMIN_UID, name, email: user.email, prof: data || {}, tab: "all", at: "users", subs: [], ct: "", cmsgs: [], q: "", nid: null, du: "all", dv: null,
    S: { htmls: [], mine: [], likes: [], prefs: { favs: [], pins: [] }, access: {}, users: [], pend: [], reqs: [], notifs: [], chats: [], chat: {}, notes: [], ann: [], allNotes: [], allHtmls: [], profiles: {} }
  };
  $("#hname").textContent = name; avatarUpd();
  $("#nav").innerHTML = ["home", "favs", "profile", "add", "mine", "notes"].map(navItem).join("");
  { const a = $("#ask"); a.classList.toggle("gold", !!ctx.admin); a.title = ctx.admin ? "Yönetim Paneli" : "Admine Soru Sor"; a.innerHTML = ctx.admin ? `<svg class="ic" viewBox="0 0 24 24">${IC.shield}</svg>` : '<svg class="ic" viewBox="0 0 24 24"><path d="M4 5h16v11H9l-5 4z"/></svg>'; }
  $("#navb").innerHTML = navItem("settings");
  $("#lo").onclick = async e => { e.preventDefault(); if (await ask("Çıkış yapılsın mı?", "Çıkış yap")) logout(); };
  startData();
  if (location.hash !== "#/home") location.hash = "#/home";
  route(); beat();
}

function clearHome() {
  ctx.subs?.forEach(u => u());
  ctx.cu?.(); ctx.chu?.(); ctx.cmu?.();
  $("#chat").hidden = true; $("#ed").hidden = true;
  if (!viewer.hidden) exitViewer();
  $("#cm").hidden = true;
  ctx = {};
  history.replaceState(null, "", location.pathname + location.search);
  ["nav", "navb", "content"].forEach(i => $("#" + i).innerHTML = "");
  shell.classList.remove("open");
}

/* HTML görüntüleme + koruma */
const HOOK = '<script>addEventListener("keydown",e=>parent.postMessage({k:e.key,c:e.ctrlKey,m:e.metaKey,s:e.shiftKey},"*"),true);addEventListener("contextmenu",e=>{e.preventDefault();((e.pointerType==="touch"||e.pointerType==="pen"||(e.sourceCapabilities&&e.sourceCapabilities.firesTouchEvents))||parent.postMessage({x:1},"*"))},true)<\/script>';
const isBad = e => {
  const k = (e.key || "").toLowerCase(), c = e.ctrlKey || e.metaKey;
  return e.key === "F12" || (c && (k === "u" || k === "s")) || (c && e.shiftKey && ["i", "j", "c"].includes(k));
};
const onKey = e => { if (isBad(e)) { e.preventDefault(); violate("Kısayol: " + e.key); } };
const touchy = e => e.pointerType === "touch" || e.pointerType === "pen" || !!e.sourceCapabilities?.firesTouchEvents;
const onCtx = e => { e.preventDefault(); if (!touchy(e)) violate("Sağ tık"); };
function devtools() {
  if (matchMedia("(pointer:fine)").matches && (outerWidth - innerWidth > 200 || outerHeight - innerHeight > 260)) return violate("DevTools (boyut)");
  if (window.eruda || window.VConsole || document.getElementById("eruda") || document.querySelector(".eruda-container,#__vconsole,script[src*=eruda i],script[src*=vconsole i]")) return violate("Eruda/vConsole");
  const t = performance.now(); debugger;
  if (performance.now() - t > 100) violate("DevTools (debugger)");
}
function guard(on) {
  if (ctx.admin) return;
  const f = on ? addEventListener : removeEventListener;
  f("keydown", onKey, true); f("contextmenu", onCtx, true);
  clearInterval(gt);
  if (on) gt = setInterval(devtools, 1500);
}
/* Sandbox içindeki HTML'ler için localStorage/sessionStorage köprüsü (veri üst sayfada, kullanıcı+HTML bazında saklanır) */
const SHIMJS = '(function(){var D=__D__,post=function(m){try{parent.postMessage({ls:m},"*")}catch(e){}};' +
  'function mk(st,persist){var A={getItem:function(k){return Object.prototype.hasOwnProperty.call(st,k)?st[k]:null},' +
  'setItem:function(k,v){k=String(k);v=String(v);st[k]=v;if(persist)post({s:[k,v]})},' +
  'removeItem:function(k){k=String(k);delete st[k];if(persist)post({r:k})},' +
  'clear:function(){for(var k in st)delete st[k];if(persist)post({c:1})},' +
  'key:function(i){var K=Object.keys(st);return i<K.length?K[i]:null}};' +
  'return new Proxy(A,{get:function(t,p){if(p==="length")return Object.keys(st).length;if(p in t)return t[p];return typeof p==="string"&&Object.prototype.hasOwnProperty.call(st,p)?st[p]:undefined},' +
  'set:function(t,p,v){A.setItem(p,v);return true},deleteProperty:function(t,p){A.removeItem(p);return true},' +
  'has:function(t,p){return p in t||Object.prototype.hasOwnProperty.call(st,p)},ownKeys:function(){return Object.keys(st)},' +
  'getOwnPropertyDescriptor:function(t,p){return Object.prototype.hasOwnProperty.call(st,p)?{value:st[p],enumerable:true,configurable:true,writable:true}:undefined}})}' +
  'var L=mk(D,true),X=mk({},false);' +
  'try{Object.defineProperty(window,"localStorage",{configurable:true,get:function(){return L}});Object.defineProperty(window,"sessionStorage",{configurable:true,get:function(){return X}})}catch(e){}})()';
const withShim = (html, data = {}) => {
  const tag = "<script>" + SHIMJS.replace("__D__", () => JSON.stringify(data).replace(/</g, "\\u003c")) + "<\/script>";
  if (/<head[^>]*>/i.test(html)) return html.replace(/<head[^>]*>/i, m => m + tag);
  if (/<html[^>]*>/i.test(html)) return html.replace(/<html[^>]*>/i, m => m + "<head>" + tag + "</head>");
  return tag + html;
};
function lsSave(m) {
  const k = ctx.lsKey; if (!k) return;
  try {
    const o = JSON.parse(localStorage.getItem(k) || "{}");
    if (m.c) for (const x in o) delete o[x]; else if (m.r != null) delete o[m.r]; else if (Array.isArray(m.s)) o[String(m.s[0]).slice(0, 200)] = String(m.s[1]);
    const j = JSON.stringify(o); if (j.length < 4e6) { localStorage.setItem(k, j); localStorage.setItem(k + "_d", "1"); clearTimeout(fst); fst = setTimeout(fsPush, 1500); }
  } catch {}
}
let fst;
async function fsPush() {
  clearTimeout(fst);
  const k = ctx.lsKey, id = ctx.lsId, uid = ctx.uid; if (!k || !id || !uid) return;
  let o; try { o = JSON.parse(localStorage.getItem(k) || "{}"); } catch { return; }
  if (JSON.stringify(o).length > 9e5) return;
  try { await setDoc(doc(db, "htmlData", uid + "_" + id), { uid, htmlId: id, data: o, ts: serverTimestamp() }); localStorage.removeItem(k + "_d"); } catch {}
}
document.addEventListener("visibilitychange", () => { if (document.hidden && ctx.lsKey && localStorage.getItem(ctx.lsKey + "_d")) fsPush(); });
addEventListener("message", e => {
  if (viewer.hidden || e.source !== frame.contentWindow) return;
  const d = e.data || {};
  if (d.ls) return lsSave(d.ls);
  if (d.v) violate(String(d.v).slice(0, 80)); else if (d.x) violate("Sağ tık"); else if (isBad({ key: d.k, ctrlKey: d.c, metaKey: d.m, shiftKey: d.s })) violate("Kısayol: " + d.k);
});
async function violate(d) {
  if (ctx.admin || vio || !ctx.uid) return;
  vio = true;
  const uid = ctx.uid;
  try { localStorage.setItem("msa_vio", JSON.stringify({ uid, d })); } catch {}
  exitViewer();
  $("#warnt").textContent = "Tespit edilen: " + d;
  $("#warn").hidden = false;
  const ok = await Promise.race([
    Promise.all([notify("violation", { detail: d }), updateDoc(doc(db, "users", uid), { status: "pending", violationAt: serverTimestamp() }).then(() => true).catch(() => false)]).then(r => r[1]),
    sleep(3000).then(() => false)
  ]);
  if (ok) try { localStorage.removeItem("msa_vio"); } catch {}
  await logout();
  $("#warnc").textContent = "Oturum kapatıldı.";
  $("#warnok").hidden = false;
  await new Promise(r => { $("#warnok").onclick = r; });
  $("#warnok").hidden = true; $("#warn").hidden = true;
  vio = false;
}
/* Yazılamayan ihlal cihazda kalır: sayfa yenilense/çevrimdışı olsa da hesap girişte onaya alınır */
{
  let f = null; try { f = JSON.parse(localStorage.getItem("msa_vio")); } catch {}
  if (f) { $("#warnt").textContent = "Tespit edilen: " + f.d; $("#warnc").textContent = "Bu cihazda güvenlik ihlali kaydedildi."; $("#warn").hidden = false; $("#warnok").hidden = false; $("#warnok").onclick = () => { $("#warnok").hidden = true; $("#warn").hidden = true; }; }
  onAuthStateChanged(auth, async u => {
    let g = null; try { g = JSON.parse(localStorage.getItem("msa_vio")); } catch {}
    if (!u || !g || g.uid !== u.uid) return;
    if (u.uid === ADMIN_UID) { try { localStorage.removeItem("msa_vio"); } catch {} return; }
    const ok = await updateDoc(doc(db, "users", u.uid), { status: "pending", violationAt: serverTimestamp() }).then(() => true).catch(() => false);
    if (ok) { notify("violation", { detail: g.d }); try { localStorage.removeItem("msa_vio"); } catch {} }
  });
}
function exitViewer() { document.body.classList.remove("vw"); if (ctx.lsKey && localStorage.getItem(ctx.lsKey + "_d")) fsPush(); frame.srcdoc = ""; viewer.hidden = true; document.body.style.overflow = ""; guard(false); }
$("#vx").onclick = exitViewer;

const KVKK_URL = "ek-/kvkk.txt";
async function kvkkHtml() {
  const r = await fetch(KVKK_URL, { cache: "no-cache" });
  if (!r.ok) throw new Error("kvkk-yok");
  const h = await r.text();
  if (!h.trim()) throw new Error("kvkk-bos");
  return h;
}
const docClick1 = e => {
  if (e.target.closest("[data-kvkk]")) { e.preventDefault(); $("#kvt").innerHTML = "<p>Yükleniyor…</p>"; $("#kvkkm").hidden = false; kvkkHtml().then(h => { $("#kvt").innerHTML = h; }).catch(() => { $("#kvt").innerHTML = "<p>Metin yüklenemedi. İnternet bağlantını kontrol edip tekrar dene.</p>"; }); }
  else if (e.target.id === "kvx" || e.target.closest("#kvx") || e.target.id === "kvkkm") $("#kvkkm").hidden = true;
};

/* Admin HTML'leri için kopyalama caydırıcıları */
function protect(html, names = []) {
  const key = Array.from(crypto.getRandomValues(new Uint8Array(12)));
  const enc = src => { const b = new TextEncoder().encode(src); let bin = ""; for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i] ^ key[i % key.length]); return btoa(bin); };
  const wrap = src => '<script>(function(k,d){var s="",i=0,b=atob(d);for(;i<b.length;i++)s+=String.fromCharCode(b.charCodeAt(i)^k[i%k.length]);var e=document.createElement("script");e.text=decodeURIComponent(escape(s));(document.head||document.documentElement).appendChild(e);e.parentNode.removeChild(e)})(' + JSON.stringify(key) + ',"' + enc(src) + '")<\/script>';
  html = html.replace(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi, (m, a, code) =>
    /\bsrc\s*=/i.test(a) || !code.trim() || (/\btype\s*=/i.test(a) && !/\btype\s*=\s*["']?(text|application)\/javascript/i.test(a)) ? m : wrap(code));
  html = html.replace(/<!--(?!\[|>)[\s\S]*?-->/g, "");
  const sigs = [...new Set(["MSA", ...names].map(x => String(x || "").trim()).filter(x => x.length >= 2))].sort((a, b) => b.length - a.length);
  if (sigs.length) {
    const re = new RegExp(sigs.map(x => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"), "gi");
    const zones = /(<script\b[\s\S]*?<\/script>|<style\b[\s\S]*?<\/style>|<textarea\b[\s\S]*?<\/textarea>|<title\b[\s\S]*?<\/title>|<svg\b[\s\S]*?<\/svg>|<option\b[\s\S]*?<\/option>|<noscript\b[\s\S]*?<\/noscript>|<[^>]*>)/i;
    html = html.split(zones).map((p, i) => i % 2 ? p : p.replace(re, m => '<span data-q="' + [...m].map(c => c.charCodeAt(0)).join(",") + '"></span>')).join("");
  }
  const codes = str => JSON.stringify([...str].map(c => c.charCodeAt(0)));
  const markCodes = JSON.stringify([...ctx.uid].map(c => c.charCodeAt(0).toString(2).padStart(8, "0")).join("").split("").map(b => b === "1" ? 8204 : 8203));
  const who = (ctx.name || "") + " · " + new Date().toLocaleDateString("tr-TR");
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="280" height="150"><text x="14" y="84" transform="rotate(-24 140 75)" font-family="sans-serif" font-size="14" font-weight="600" fill="#888">' + esc(who) + '</text></svg>';
  const bg = "position:fixed;inset:0;z-index:2147483647;pointer-events:none;opacity:.1;background-image:url('data:image/svg+xml," + encodeURIComponent(svg) + "')";
  const guardJs = '(function(){var P=function(v){try{parent.postMessage({v:v},"*")}catch(e){}};' +
    'var T=function(a){return String.fromCharCode.apply(null,a)};' +
    '[["copyright",' + codes("MSA - Tüm hakları saklıdır") + '],["x-viewer",' + codes(ctx.uid) + ']].forEach(function(p){var m=document.createElement("meta");m.name=p[0];m.content=T(p[1]);(document.head||document.documentElement).appendChild(m)});' +
    'var fq=function(){var q=document.querySelectorAll("span[data-q]");for(var i=0;i<q.length;i++){var c=q[i].getAttribute("data-q").split(","),s="";for(var j=0;j<c.length;j++)s+=String.fromCharCode(+c[j]);q[i].textContent=s;q[i].removeAttribute("data-q")}};' +
    'var sg=function(){var d=document.createElement("div");d.style.cssText="position:absolute;width:0;height:0;overflow:hidden";d.textContent=String.fromCharCode(169)+T(' + markCodes + ');document.body.insertBefore(d,document.body.firstChild);fq()};' +
    '["contextmenu","selectstart","copy","cut","dragstart","beforeprint"].forEach(function(t){addEventListener(t,function(e){var n=e.target&&e.target.nodeName;if(t==="selectstart"&&/INPUT|TEXTAREA/.test(n))return;e.preventDefault();if(t==="contextmenu"&&!(e.pointerType==="touch"||e.pointerType==="pen"||(e.sourceCapabilities&&e.sourceCapabilities.firesTouchEvents)))P("Sag tik")},true)});' +
    'addEventListener("keydown",function(e){var k=(e.key||"").toLowerCase(),c=e.ctrlKey||e.metaKey;if(e.key==="F12"||(c&&["u","s","p"].indexOf(k)>-1)||(c&&e.shiftKey&&["i","j","c"].indexOf(k)>-1)){e.preventDefault();P("Kisayol: "+e.key)}},true);' +
    'var S=' + JSON.stringify(bg) + ',ob=new MutationObserver(function(){var w=document.getElementById("wm");if(!w)return mk();if(w.getAttribute("style")!==S){mk();P("Filigran degistirildi")}});' +
    'var mk=function(){var w=document.getElementById("wm");if(!w){w=document.createElement("div");w.id="wm";document.body.appendChild(w)}w.setAttribute("style",S);ob.observe(w,{attributes:true})};' +
    'var ready=function(){mk();sg();ob.observe(document.body,{childList:true})};' +
    'if(document.body)ready();else document.addEventListener("DOMContentLoaded",ready);' +
    'setInterval(function(){var t=performance.now();debugger;if(performance.now()-t>100)P("DevTools (iframe)")},1500)})()';
  const css = '<style>*{-webkit-user-select:none;user-select:none;-webkit-touch-callout:none}input,textarea,[contenteditable]{-webkit-user-select:text;user-select:text}@media print{html{display:none!important}}</style>';
  const inj = css + wrap(guardJs);
  if (/<head[^>]*>/i.test(html)) html = html.replace(/<head[^>]*>/i, m => m + inj);
  else if (/<html[^>]*>/i.test(html)) html = html.replace(/<html[^>]*>/i, m => m + "<head>" + inj + "</head>");
  else html = inj + html;
  return html;
}

const canFree = () => !!(ctx.admin || ctx.prof?.trusted);
async function openHtml(id, h) {
  const S = ctx.S;
  if (needMail() && h.by !== ctx.uid) { location.hash = "#/profile"; return toast("Paylaşılan HTML'leri açmak için profilinden e-posta ekle."); }
  if (!ctx.admin && h.by !== ctx.uid && S.access[id] !== "granted" && !(h.by === ADMIN_UID && ctx.prof?.trusted)) {
    if (S.access[id] === "requested") return toast("İsteğin admin onayını bekliyor.");
    await setDoc(doc(db, "access", ctx.uid + "_" + id), { uid: ctx.uid, name: ctx.name, htmlId: id, title: h.title, status: "requested", ts: serverTimestamp() });
    S.access[id] = "requested";
    notify("access_request", { detail: h.title }); 
    return toast("Açma isteği admine gönderildi.");
  }
  const b = await getDoc(doc(db, "htmlBodies", id));
  if (!b.exists()) return toast("İçerik bulunamadı.");
  ctx.lsKey = "msa_ls_" + ctx.uid + "_" + id; ctx.lsId = id; let ld = {}; try { ld = JSON.parse(localStorage.getItem(ctx.lsKey) || "{}"); } catch {}
  if (!localStorage.getItem(ctx.lsKey + "_d")) {
    try {
      const r = await getDoc(doc(db, "htmlData", ctx.uid + "_" + id));
      if (r.exists()) { ld = r.data().data || {}; localStorage.setItem(ctx.lsKey, JSON.stringify(ld)); }
      else if (Object.keys(ld).length) fsPush();
    } catch {}
  }
  frame.srcdoc = withShim((h.by === ADMIN_UID && !ctx.admin ? protect(b.data().html, [h.byName]) : b.data().html) + (ctx.admin ? "" : HOOK), ld);
  viewer.hidden = false; document.body.style.overflow = "hidden"; document.body.classList.add("vw");
  guard(true);
}

/* Yorumlar */
function cmRender() {
  const L = (ctx.cl || []).filter(c => ctx.admin || !c.deleted), by = (a, b) => ms(a.ts) - ms(b.ts);
  const it = (c, l) => `<div class="cmi l${l}">${avHtml(c.uid, c.name, "av xs")}<b>${esc(c.name)}${vb(c.uid)}</b>${c.deleted ? ' <em class="bd st-blocked">kullanıcı sildi</em>' : ""} <small>${fmt(c.ts)}</small><p>${esc(c.text)}</p><div><button data-a="rep" data-id="${l ? c.parent : c.id}" data-n="${esc(c.name)}">Cevapla</button>${c.uid === ctx.uid || ctx.admin ? `<button data-a="cdel" data-id="${c.id}">Sil</button>` : ""}</div></div>`;
  $("#cml").innerHTML = L.filter(c => !c.parent).sort(by).map(c => it(c, 0) + L.filter(r => r.parent === c.id).sort(by).map(r => it(r, 1)).join("")).join("") || '<p class="muted">Henüz yorum yok.</p>';
  $("#rep").hidden = !ctx.rep;
  $("#rep").textContent = ctx.rep ? "Cevap: " + ctx.rep.n + " (iptal için dokun)" : "";
}
function openComments(id, h) {
  ctx.cm = id; ctx.rep = null; ctx.cl = [];
  $("#cmt").textContent = h.title; $("#cm").hidden = false; cmRender();
  ctx.cu?.();
  ctx.cu = onSnapshot(query(collection(db, "comments"), where("htmlId", "==", id)), s => { ctx.cl = s.docs.map(d => ({ id: d.id, ...d.data() })); cmRender(); }, () => {});
}
function closeComments() { ctx.cu?.(); ctx.cu = null; ctx.cm = null; $("#cm").hidden = true; }

/* Olaylar */
const docClick2 = e => {
  if (!ctx.xid) return;
  const c = e.target.closest(".card2");
  if (c && c.dataset.id === ctx.xid) return;
  xpOff();
};
const homeClick1 = async e => {
  const b = e.target.closest("[data-a],[data-t],[data-at]");
  if (!b) return;
  const d = b.dataset, id = d.id, S = ctx.S;
  if (d.t) { ctx.tab = d.t; return render(); }
  if (d.at) { ctx.at = d.at; if (d.at === "data") loadProf(); return render(); }
  const h = [...S.htmls, ...S.mine].find(x => x.id === id);
  try {
    switch (d.a) {
      case "uxp": ctx.uxp = ctx.uxp === id ? null : id; render(); break;
      case "openh": if (h) { xpOff(); await openHtml(id, h); } break;
      case "open":
        if (!h) break;
        if (ctx.xid === id) xpOff(); else { xpOff(); xpOn(b); }
        break;
      case "like": {
        if (spam("l" + id, 1500)) break;
        const k = doc(db, "likes", id + "_" + ctx.uid), on = S.likes.some(l => l.htmlId === id && l.uid === ctx.uid);
        if (on) await deleteDoc(k); else await setDoc(k, { htmlId: id, uid: ctx.uid });
        break;
      }
      case "fav": case "pin": {
        const f = d.a === "fav" ? "favs" : "pins", on = S.prefs[f].includes(id);
        await setDoc(doc(db, "prefs", ctx.uid), { [f]: on ? arrayRemove(id) : arrayUnion(id) }, { merge: true });
        break;
      }
      case "edit": if (h) await openEditor(h); break;
      case "cm": if (h) openComments(id, h); break;
      case "cx": closeComments(); break;
      case "rep": ctx.rep = { id, n: d.n }; cmRender(); $("#cmx").focus(); break;
      case "rcancel": ctx.rep = null; cmRender(); break;
      case "cdel": {
        const c = (ctx.cl || []).find(x => x.id === id);
        if (ctx.admin) {
          const rs = (ctx.cl || []).filter(x => x.parent === id), k = rs.filter(r => !r.deleted).length + (c && !c.deleted ? 1 : 0);
          for (const r of rs) await deleteDoc(doc(db, "comments", r.id));
          await deleteDoc(doc(db, "comments", id)); bumpCc(ctx.cm, -k);
        }
        else { await updateDoc(doc(db, "comments", id), { deleted: true, deletedAt: serverTimestamp() }); if (c && !c.deleted) bumpCc(ctx.cm, -1); }
        break;
      }
      case "trust": {
        const on = d.v === "1";
        if (!await ask(on ? d.n + " kullanıcısına şu yetkiler verilsin mi: e-posta muafiyeti, mavi tik, admin HTML'lerine onaysız giriş, HTML yükleme ve düzenlemede onaysız yayın? (Güvenlik ihlalleri yine bildirilir.)" : d.n + " kullanıcısının güvenilir yetkileri (muafiyet, mavi tik, onaysız giriş/yayın) kaldırılsın mı?", on ? "Onayla" : "Kaldır")) break;
        const bg = ctx.S.badges || [];
        await updateDoc(doc(db, "users", id), { trusted: on, mailExempt: on });
        await setDoc(doc(db, "settings", "badges"), { uids: on ? (bg.includes(id) ? bg : [...bg, id]) : bg.filter(x => x !== id) }, { merge: true });
        toast(on ? "Güvenilir yetkisi verildi." : "Güvenilir yetkisi kaldırıldı.");
        break;
      }
      case "mex": await updateDoc(doc(db, "users", id), { mailExempt: d.v === "1" }); break;
      case "udel": if (await ask(d.n + " ve tüm verileri kalıcı olarak silinsin mi?", "Sil")) { await wipeUser(id); toast("Kullanıcı silindi."); } break;
      case "ust": await updateDoc(doc(db, "users", id), { status: d.v, ...(d.v === "approved" ? { violationAt: null } : {}) }); break;
      case "hap": await updateDoc(doc(db, "htmls", id), { status: "approved" }); break;
      case "hrej": await wipeHtml(id); break;
      case "acc": await updateDoc(doc(db, "access", id), { status: d.v }); break;
      case "nall": { const w = writeBatch(db); ctx.S.notifs.filter(n => !n.read).forEach(n => w.update(doc(db, "notifications", n.id), { read: true })); await w.commit(); break; }
      case "nclr": if (await ask("Tüm bildirimler silinsin mi?", "Sil")) { await delCol(collection(db, "notifications")); toast("Bildirimler temizlendi."); } break;
      case "nread":
        await updateDoc(doc(db, "notifications", id), { read: true });
        ctx.at = d.k === "new_user" ? "users" : d.k === "chat" ? "msgs" : "pend"; $("#notif").hidden = true;
        if (location.hash === "#/admin") render(); else location.hash = "#/admin"; break;
    }
  } catch (x) { toast(trError(x)); }
};

const homeSubmit1 = async e => {
  const f = e.target.id;
  if (f !== "addf" && f !== "cmf") return;
  e.preventDefault();
  try {
    if (f === "cmf") {
      const x = $("#cmx").value.trim();
      if (!x || spam("c", 3000, x)) return;
      await addDoc(collection(db, "comments"), { htmlId: ctx.cm, uid: ctx.uid, name: ctx.name, text: x, parent: ctx.rep?.id || null, ts: serverTimestamp() });
      bumpCc(ctx.cm, 1);
      $("#cmx").value = ""; ctx.rep = null; cmRender();
      return;
    }
    const t = $("#ht").value.trim(), d = $("#hd").value.trim(), h = $("#hh").value;
    if (!t || !h.trim()) return setErr("add", "Başlık ve HTML gerekli.");
    if (h.length > 900000) return setErr("add", "HTML çok büyük (en fazla ~900 KB).");
    setErr("add");
    const ref = doc(collection(db, "htmls")), w = writeBatch(db);
    w.set(ref, { title: t, desc: d, by: ctx.uid, byName: ctx.name, status: canFree() ? "approved" : "pending", createdAt: serverTimestamp() });
    w.set(doc(db, "htmlBodies", ref.id), { html: h, by: ctx.uid });
    await w.commit();
    if (!canFree()) notify("html_pending", { detail: t });
    toast(ctx.admin ? "Yayınlandı." : "Admin onayına gönderildi.");
    location.hash = "#/mine";
  } catch (x) { f === "addf" ? setErr("add", trError(x)) : toast(trError(x)); }
};

/* Sohbet */
const bub = (m, mine) => `<div class="mg ${mine ? "u" : "a"}">${(() => { const id = m.from === "admin" ? ADMIN_UID : (ctx.admin ? ctx.ct : ctx.uid); return avHtml(id, m.from === "admin" ? "A" : (ctx.admin ? (ctx.S.users.find(u => u.id === ctx.ct)?.username || "") : ctx.name), "av xs"); })()}${esc(m.text)}${ctx.admin && m.id ? `<button class="mgx" data-a="mdel" data-id="${m.id}" aria-label="Sil">×</button>` : ""}</div>`;
function chatDraw() {
  $("#chn").innerHTML = avHtml(ADMIN_UID, "A", "av sm") + "Admin ile Sohbet";
  const l = $("#chl"), c = ctx.S.chat?.userClearedAt || 0;
  const m = (ctx.chd || []).map(d => d.data()).filter(x => ms(x.ts) > c);
  l.innerHTML = m.map(x => bub(x, x.from === "user")).join("") || '<p class="muted">Admine bir mesaj yaz.</p>';
  l.scrollTo(0, 1e9);
}
function chatOpen() {
  $("#chat").hidden = false;
  ctx.chu?.();
  ctx.chu = onSnapshot(query(collection(db, "chats", ctx.uid, "msgs"), orderBy("ts")), s => { ctx.chd = s.docs; chatDraw(); }, () => {});
  if (ctx.S.chat?.userUnread) setDoc(doc(db, "chats", ctx.uid), { userUnread: 0 }, { merge: true }).catch(() => {});
}
function chatClose() { ctx.chu?.(); ctx.chu = null; $("#chat").hidden = true; }
$("#ask").onclick = () => {
  if (ctx.admin) { location.hash === "#/admin" ? render() : location.hash = "#/admin"; }
  else $("#chat").hidden ? chatOpen() : chatClose();
};

const homeClick2 = e => {
  const b = e.target.closest("[data-a]");
  if (!b) return;
  const d = b.dataset;
  if (d.a === "chx") chatClose();
  if (d.a === "openchat") { $("#notif").hidden = true; chatOpen(); }
  if (d.a === "ch") openAdminChat(d.id);
};

const homeSubmit2 = async e => {
  const f = e.target.id;
  if (f !== "chf" && f !== "adf") return;
  e.preventDefault();
  const adm = f === "adf", inp = adm ? $("#adx") : $("#chi"), x = inp.value.trim(), u = adm ? ctx.ct : ctx.uid;
  if (!x || !u || spam("m", 2000, x)) return;
  inp.value = "";
  try {
    await addDoc(collection(db, "chats", u, "msgs"), { from: adm ? "admin" : "user", text: x, ts: serverTimestamp() });
    await setDoc(doc(db, "chats", u), adm
      ? { uid: u, name: ctx.S.users.find(z => z.id === u)?.username || "", last: x, lastBy: "admin", updated: serverTimestamp(), userUnread: increment(1), adminUnread: 0 }
      : { uid: u, name: ctx.name, last: x, lastBy: "user", updated: serverTimestamp(), adminUnread: increment(1) }, { merge: true });
    if (!adm) notify("chat", { detail: x.slice(0, 80) });
  } catch (x2) { toast(trError(x2)); }
};

/* Kod editörü */
const PAL = ["#8b5cf6", "#3b82f6", "#06b6d4", "#22c55e", "#eab308", "#f97316", "#ef4444", "#ec4899"];
const cardColor = h => /^#[0-9a-f]{6}$/i.test(h.fc || "") ? h.fc : PAL[[...String(h.id || "")].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 0) % PAL.length];
const edh = $("#edh"), edpre = $("#edpre"), edn = $("#edn"), edf = $("#edf"), edb = $("#ed");
let edT, edNT, edRows = [], edCur = 0;
const edm = document.createElement("div"); edm.id = "edm"; edm.setAttribute("aria-hidden", "true"); edh.parentElement.prepend(edm);
/* Satır numaraları: mantıksal satır başına bir numara, kaydırılan (sarılan) satırlar için boşluk */
function edNum(line) {
  if (line !== undefined) edCur = line;
  const L = edh.value.split("\n"), w = edh.clientWidth, lh = parseFloat(getComputedStyle(edh).lineHeight) || 20;
  if (w > 40) {
    edm.style.width = w + "px";
    edm.innerHTML = L.map(l => "<div>" + (esc(l) || " ") + "</div>").join("");
    const k = edm.children; edRows = L.map((_, i) => Math.max(1, Math.round(k[i].offsetHeight / lh)));
    edm.innerHTML = "";
  } else edRows = L.map(() => 1);
  edn.innerHTML = L.map((_, i) => '<div style="height:' + edRows[i] * lh + 'px">' + (edCur === i + 1 ? '<b class="cln">' + (i + 1) + "</b>" : i + 1) + "</div>").join("");
  edn.scrollTop = edh.scrollTop;
}
const edNumQ = () => { cancelAnimationFrame(edNT); edNT = requestAnimationFrame(() => edNum()); };
const edY = n => { let r = 0; for (let i = 0; i < n - 1 && i < edRows.length; i++) r += edRows[i]; return r * (parseFloat(getComputedStyle(edh).lineHeight) || 20); };
new ResizeObserver(edNumQ).observe(edh);

/* Renklendirme: HTML (içinde JS/CSS dahil), JS/TS ve C-benzeri diller, Python/Shell/YAML, SQL, CSS, JSON, Markdown ve düz metin */
const KW = {
  c: "abstract as async await boolean break byte case catch char class const constructor continue debugger default defer delete do double else enum export extends extern final finally float fn for func function go goto if impl implements import in instanceof int interface internal let long match mod mut namespace new nil null of override package private protected pub public readonly ref return sealed short signed sizeof static string struct super switch this throw throws trait true false try type typedef typeof undefined union unsafe unsigned use using var virtual void volatile where while with yield echo elseif endif endwhile foreach array isset unset print require include",
  py: "and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield None True False self cls print then fi do done esac case function export local echo source alias unset true false null",
  sql: "select from where insert into values update set delete create alter drop table index view join left right inner outer full cross on as and or not null is in like between group by order having limit offset union all distinct case when then else end primary key foreign references default unique check constraint database use begin commit rollback"
};
const KWS = {}; for (const k in KW) KWS[k] = new Set(KW[k].split(" "));
const EXT = { html: "html", htm: "html", xhtml: "html", svg: "html", xml: "html", vue: "html", css: "css", scss: "css", less: "css", json: "json", js: "c", mjs: "c", cjs: "c", jsx: "c", ts: "c", tsx: "c", java: "c", kt: "c", c: "c", h: "c", cpp: "c", hpp: "c", cs: "c", go: "c", rs: "c", php: "c", swift: "c", dart: "c", py: "py", sh: "py", bash: "py", zsh: "py", rb: "py", yml: "py", yaml: "py", toml: "py", ini: "py", env: "py", sql: "sql", md: "md", markdown: "md", txt: "" };
let edLang = "";
function detectLang(s) {
  const h = s.slice(0, 4000);
  if (/^\s*(<!doctype|<html|<head|<body|<\?xml|<svg|<[a-z][\w-]*[\s>])/i.test(h) || (/<\/?[a-z][\w-]*[^>]*>/i.test(h) && /<\/(div|p|body|html|script|style|span|a|ul|table)>/i.test(h))) return "html";
  if (/^\s*[\[{]\s*("|\[|\{|\d|\]|\})/.test(s) && /[\]}]\s*$/.test(s)) return "json";
  if (/^\s*#{1,6}\s|^\s*[-*]\s+\S|^```/m.test(h) && !/[{};]\s*$/m.test(h)) return "md";
  if (/^\s*(select|insert|update|delete|create|alter|drop)\s/im.test(h)) return "sql";
  if (/^\s*(def |class \w+(\(.*\))?:|import \w+|from \w+ import|#!\/|[\w.-]+:\s)/m.test(h) && !/[{};]\s*$/m.test(h)) return "py";
  if (/(^|\n)\s*[^{}\n]+\{[^{}]*:[^{}]*\}/.test(h) && !/\b(function|const|let|var|=>)\b/.test(h)) return "css";
  return "c";
}
function hlCode(s, f) {
  if (f === "md") return s.split("\n").map(l => /^\s*(#{1,6}\s|>|```)/.test(l) ? `<i class="${/^\s*#/.test(l) ? "k" : "c"}">${esc(l)}</i>` : esc(l).replace(/(\*\*[^*\n]+\*\*|`[^`\n]+`)/g, '<i class="s">$1</i>').replace(/^(\s*(?:[-*+]|\d+\.)\s)/, '<i class="t">$1</i>')).join("\n");
  if (!f) return esc(s);
  const sq = `"(?:\\\\[\\s\\S]|[^"\\\\\\n])*"?|'(?:\\\\[\\s\\S]|[^'\\\\\\n])*'?`;
  const alt = f === "css" ? ["\\/\\*[\\s\\S]*?(?:\\*\\/|$)", sq, "#[0-9a-fA-F]{3,8}\\b|-?\\d[\\d.]*(?:px|em|rem|vh|vw|%|s|ms|deg|fr)?", "@[\\w-]+|[\\w-]+(?=\\s*:)"]
    : f === "json" ? ["(?!)", '"(?:\\\\.|[^"\\\\\\n])*"?', "-?\\d[\\d.eE+-]*", "\\b(?:true|false|null)\\b"]
    : f === "py" ? ["#[^\\n]*", '"""[\\s\\S]*?(?:"""|$)|\'\'\'[\\s\\S]*?(?:\'\'\'|$)|' + sq, "\\b\\d[\\w.]*", "[A-Za-z_$][\\w$]*"]
    : f === "sql" ? ["--[^\\n]*|\\/\\*[\\s\\S]*?(?:\\*\\/|$)", sq, "\\b\\d[\\w.]*", "[A-Za-z_][\\w]*"]
    : ["\\/\\/[^\\n]*|\\/\\*[\\s\\S]*?(?:\\*\\/|$)", sq + "|`(?:\\\\[\\s\\S]|[^`\\\\])*`?", "\\b\\d[\\w.]*", "[A-Za-z_$][\\w$]*"];
  const re = new RegExp(`(${alt[0]})|(${alt[1]})|(${alt[2]})|(${alt[3]})`, "g"), kw = KWS[f === "sql" ? "sql" : f === "py" ? "py" : "c"];
  let o = "", i = 0, m;
  while ((m = re.exec(s))) {
    if (m[0] === "") { re.lastIndex++; continue; }
    o += esc(s.slice(i, m.index)); i = m.index + m[0].length;
    const t = m[0], e = esc(t);
    if (m[1]) o += `<i class="c">${e}</i>`;
    else if (m[2]) o += f === "json" && /^\s*:/.test(s.slice(i)) ? `<i class="a">${e}</i>` : `<i class="s">${e}</i>`;
    else if (m[3]) o += `<i class="n">${e}</i>`;
    else if (f === "css") o += t[0] === "@" ? `<i class="k">${e}</i>` : `<i class="a">${e}</i>`;
    else if (f === "json") o += `<i class="k">${e}</i>`;
    else o += kw.has(f === "sql" ? t.toLowerCase() : t) ? `<i class="k">${e}</i>` : e;
  }
  return o + esc(s.slice(i));
}
function hl(s, f) {
  f = f || edLang || detectLang(s);
  if (f !== "html") return hlCode(s, f);
  const tag = t => {
    const m = t.match(/^(<\/?!?)([\w:-]*)([\s\S]*?)(\/?>?)$/);
    const a = m[3].replace(/([\w:@.-]+)(\s*=\s*)?("[^"]*"|'[^']*'|[^\s"'>]+)?|([\s\S])/g,
      (x, n, q, v, o) => o !== undefined ? esc(o) : `<i class="a">${esc(n)}</i>${esc(q || "")}${v ? `<i class="s">${esc(v)}</i>` : ""}`);
    return `<i class="t">${esc(m[1] + m[2])}</i>${a}<i class="t">${esc(m[4])}</i>`;
  };
  let o = "", i = 0;
  while (i < s.length) {
    if (s.startsWith("<!--", i)) {
      let j = s.indexOf("-->", i); j = j < 0 ? s.length : j + 3;
      o += `<i class="c">${esc(s.slice(i, j))}</i>`; i = j;
    } else if (s[i] === "<" && /[\w\/!]/.test(s[i + 1] || "")) {
      let j = i + 1, q = "";
      for (; j < s.length; j++) {
        const c = s[j];
        if (q) { if (c === q) q = ""; } else if (c === '"' || c === "'") q = c; else if (c === ">") { j++; break; }
      }
      const tg = s.slice(i, j); o += tag(tg); i = j;
      const sm = tg.match(/^<(script|style)\b/i);
      if (sm && !/\/>$/.test(tg)) {
        const mm = s.slice(i).search(new RegExp("</" + sm[1] + "\\b", "i")), k = mm < 0 ? s.length : i + mm;
        o += hlCode(s.slice(i, k), sm[1].toLowerCase() === "style" ? "css" : /json/i.test(tg) ? "json" : "c"); i = k;
      }
    } else {
      let j = s.indexOf("<", i + 1); if (j < 0) j = s.length;
      o += esc(s.slice(i, j)); i = j;
    }
  }
  return o;
}

function edSync() {
  const v = edh.value;
  edpre.innerHTML = (v.length > 120000 ? esc(v) : hl(v)) + "\n";
  if ($("#edfb").hidden) edCur = 0;
  edNumQ();
  clearTimeout(edT);
  edT = setTimeout(() => edf.srcdoc = withShim(v), 300);
  if (typeof edFind === "function" && !$("#edfb").hidden) edFind(true);
  try { clearTimeout(ht); ht = setTimeout(hpush, 500); } catch {}
}
edh.addEventListener("input", edSync);
/* Yapıştırma: biçimsiz düz metin, temizlenmiş kod */
const cleanCode = t => t.replace(/\r\n?/g, "\n").replace(/[\u200B\u2060\uFEFF]/g, "").replace(/\u00A0/g, " ").replace(/=\s*[“”„]([^“”„"<>\n]*)[“”„]/g, '="$1"');
function edInsert(t) { edh.setRangeText(cleanCode(t), edh.selectionStart, edh.selectionEnd, "end"); edSync(); }
edh.addEventListener("paste", e => {
  const t = e.clipboardData && e.clipboardData.getData("text/plain");
  if (t == null || t === "") return;
  e.preventDefault(); edInsert(t);
});
$("#edpaste").onclick = async () => {
  try { const t = await navigator.clipboard.readText(); if (!t) return toast("Panoda metin yok."); edInsert(t); edh.focus(); }
  catch { toast("Pano erişimi reddedildi. Kod kutusuna uzun basıp yapıştırabilir veya dosyadan yükleyebilirsin."); }
};
async function edLoad(f) {
  if (f.size > 900000) return toast("Dosya çok büyük (en fazla ~900 KB).");
  try {
    const buf = await f.arrayBuffer(); let t;
    try { t = new TextDecoder("utf-8", { fatal: true }).decode(buf); } catch { t = new TextDecoder("windows-1254").decode(buf); }
    edLang = EXT[(f.name.split(".").pop() || "").toLowerCase()] ?? ""; edh.value = cleanCode(t); edh.scrollTop = edh.scrollLeft = 0; edSync();
    { const e = ctx.ed; if (!(e.mt ?? e.h.title)) { const m = t.match(/<title[^>]*>([\s\S]*?)<\/title>/i); e.mt = ((m && m[1].trim()) || f.name.replace(/\.[^.]+$/, "")).slice(0, 80); } }
    edb.classList.remove("pv"); $$(".edtabs button").forEach(x => x.classList.toggle("on", x.dataset.ed === "code"));
    toast("Dosya yüklendi.");
  } catch { toast("Dosya okunamadı."); }
}
$("#edfile").onclick = () => $("#edfin").click();
$("#edfin").onchange = e => { const f = e.target.files[0]; e.target.value = ""; if (f) edLoad(f); };
edb.addEventListener("dragover", e => e.preventDefault());
edb.addEventListener("drop", e => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) edLoad(f); });
/* Geri al/yinele, bul-değiştir, otomatik kapanış etiketi */
let hist = [], hi = -1, ht;
const hpush = () => { clearTimeout(ht); if (hist[hi]?.v === edh.value) return; hist.splice(hi + 1); hist.push({ v: edh.value, s: edh.selectionStart }); if (hist.length > 200) hist.shift(); hi = hist.length - 1; updUR(); };
const hgo = d => {
  hpush(); const n = hi + d; if (n < 0 || n >= hist.length) return;
  const o = edh.value, v = hist[n].v, st = edh.scrollTop, sl = edh.scrollLeft;
  let a = 0; const m = Math.min(o.length, v.length); while (a < m && o[a] === v[a]) a++;
  let b = 0; while (b < m - a && o[o.length - 1 - b] === v[v.length - 1 - b]) b++;
  const c = v.length - b; hi = n;
  edh.focus({ preventScroll: true }); edh.value = v; edh.setSelectionRange(c, c); edSync(); updUR();
  edNum(); const lh = parseFloat(getComputedStyle(edh).lineHeight) || 18, y = edY(v.slice(0, c).split("\n").length + 1);
  edh.scrollLeft = sl;
  edh.scrollTop = (y < st + lh || y > st + edh.clientHeight - 2 * lh) ? Math.max(0, y - edh.clientHeight / 2) : st;
};
function updUR() { $("#edundo").classList.toggle("off", hi <= 0 && edh.value === (hist[0]?.v ?? edh.value)); $("#edredo").classList.toggle("off", hi >= hist.length - 1); }
const hreset = () => { clearTimeout(ht); hist = [{ v: edh.value, s: 0 }]; hi = 0; updUR(); };
edh.addEventListener("input", e => {
  updUR(); clearTimeout(ht); ht = setTimeout(hpush, 500);
  if (e.inputType && e.inputType.startsWith("insert") && e.inputType !== "insertFromPaste" && e.data && e.data.endsWith(">")) {
    const pos = edh.selectionStart, m = edh.value.slice(0, pos).match(/<([a-zA-Z][\w-]*)(\s[^<>]*)?>$/);
    if (m && !(m[2] || "").trim().endsWith("/") && !/^(br|img|input|meta|link|hr|area|base|col|embed|source|track|wbr|param)$/i.test(m[1])) {
      hpush(); edh.setRangeText("</" + m[1] + ">", pos, pos, "start"); edSync();
    }
  }
});
$("#edundo").onclick = () => hgo(-1); $("#edredo").onclick = () => hgo(1);
edh.addEventListener("keydown", e => {
  if ((e.ctrlKey || e.metaKey) && !e.altKey) { const k = e.key.toLowerCase(); if (k === "z") { e.preventDefault(); hgo(e.shiftKey ? 1 : -1); } else if (k === "y") { e.preventDefault(); hgo(1); } }
});
const vvFit = () => { const vv = window.visualViewport; if (vv && !edb.hidden) edb.style.setProperty("--vt", vv.offsetTop + "px"); };
if (window.visualViewport) { visualViewport.addEventListener("resize", vvFit); visualViewport.addEventListener("scroll", vvFit); }
/* Bul: eşleşmeleri renklendirir, satır numarasını gösterir, oraya kaydırır */
const edmk = $("#edmk");
let fm = [], fi = 0;
const escRe = t => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
function edFind(keep) {
  const bar = !$("#edfb").hidden, f = $("#edfind").value, v = edh.value;
  fm = [];
  if (bar && f) { const re = new RegExp(escRe(f), "gi"); let m; while ((m = re.exec(v)) && fm.length < 5000) { fm.push(m.index); if (!m[0].length) re.lastIndex++; } }
  if (!keep) fi = 0;
  fi = Math.max(0, Math.min(fi, fm.length - 1));
  edMark();
}
function edMark() {
  const bar = !$("#edfb").hidden, f = $("#edfind").value, v = edh.value;
  if (!bar || !f || !fm.length) {
    edmk.innerHTML = ""; $("#edfi").textContent = bar && f ? "Bulunamadı" : "";
    if (edCur) edNum(0);
    return;
  }
  const cur = fm[fi], L = f.length, ls = v.lastIndexOf("\n", cur - 1) + 1;
  let le = v.indexOf("\n", cur); if (le < 0) le = v.length;
  const seg = (a, b) => { let o = "", q = a; for (const i of fm) { if (i + L <= a) continue; if (i >= b) break; o += esc(v.slice(q, i)) + `<mark class="${i === cur ? "mc" : ""}">` + esc(v.slice(i, i + L)) + "</mark>"; q = i + L; } return o + esc(v.slice(q, b)); };
  edmk.innerHTML = seg(0, ls) + '<span class="cl">' + seg(ls, le) + "</span>" + seg(le, v.length) + "\n";
  const line = v.slice(0, cur).split("\n").length;
  $("#edfi").textContent = (fi + 1) + "/" + fm.length + " · Satır " + line + " · Sütun " + (cur - ls + 1);
  edNum(line);
  edmk.scrollTop = edh.scrollTop; edmk.scrollLeft = edh.scrollLeft; edn.scrollTop = edh.scrollTop;
}
function edGo() {
  if (!fm.length) return;
  const v = edh.value, cur = fm[fi], ls = v.lastIndexOf("\n", cur - 1) + 1, line = v.slice(0, cur).split("\n").length;
  const cs = getComputedStyle(edh), lh = parseFloat(cs.lineHeight) || 20;
  edh.scrollTop = Math.max(0, edY(line) - edh.clientHeight * 0.2);
}
const edStep = d => { if (!fm.length) return; fi = (fi + d + fm.length) % fm.length; edMark(); edGo(); };
$("#edfbt").onclick = () => { const b = $("#edfb"); b.hidden = !b.hidden; if (!b.hidden) { hHead(true); $("#edfind").focus(); } edFind(); edGo(); };
$("#edfx").onclick = () => { $("#edfb").hidden = true; edFind(); };
$("#edfind").addEventListener("input", () => { edFind(); edGo(); });
$("#edfind").addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); edStep(e.shiftKey ? -1 : 1); } });
$("#edfn").onclick = () => edStep(1); $("#edfp").onclick = () => edStep(-1);
$("#edfr").onclick = () => {
  if (!fm.length) return;
  hpush(); const i = fm[fi], f = $("#edfind").value;
  edh.value = edh.value.slice(0, i) + $("#edrep").value + edh.value.slice(i + f.length); edSync(); edGo();
};
$("#edfa").onclick = () => {
  const f = $("#edfind").value; if (!f || !fm.length) return toast("Bulunamadı.");
  const n = fm.length; hpush(); edh.value = edh.value.replace(new RegExp(escRe(f), "gi"), () => $("#edrep").value); edSync(); toast(n + " yer değiştirildi.");
};
/* Üst araçlar ok tuşuyla göster/gizle */
const hHead = on => edb.classList.toggle("hc", on);
$("#edhd").onclick = () => hHead(!edb.classList.contains("hc"));
edh.addEventListener("scroll", () => { edpre.scrollTop = edmk.scrollTop = edn.scrollTop = edh.scrollTop; edpre.scrollLeft = edmk.scrollLeft = edh.scrollLeft; });
edh.addEventListener("keydown", e => {
  if (e.key === "Tab") { e.preventDefault(); edh.setRangeText("  ", edh.selectionStart, edh.selectionEnd, "end"); edSync(); }
});

{
  let d0 = 0, f0 = 13;
  const dist = t => Math.hypot(t[0].clientX - t[1].clientX, t[0].clientY - t[1].clientY);
  edh.addEventListener("touchstart", e => { if (e.touches.length === 2) { d0 = dist(e.touches); f0 = parseFloat(getComputedStyle(edb).getPropertyValue("--fs")) || 13; } }, { passive: true });
  edh.addEventListener("touchmove", e => {
    if (e.touches.length !== 2 || !d0) return;
    e.preventDefault();
    const f = Math.min(30, Math.max(9, Math.round(f0 * dist(e.touches) / d0 * 2) / 2));
    edb.style.setProperty("--fs", f + "px"); edb.style.setProperty("--lh", Math.round(f * 1.55) + "px"); edNumQ();
  }, { passive: false });
  edh.addEventListener("touchend", () => { d0 = 0; });
}
$$(".edtabs button").forEach(b => b.onclick = () => {
  $$(".edtabs button").forEach(x => x.classList.toggle("on", x === b));
  edb.classList.toggle("pv", b.dataset.ed === "prev");
});

async function openEditor(h) {
  const isNew = !h;
  if (isNew) h = { id: null, title: "", desc: "", by: ctx.uid };
  const b = isNew ? null : await getDoc(doc(db, "htmlBodies", h.id)), code = b?.exists() ? b.data().html : "";
  $("#edel").hidden = isNew;
  ctx.ed = { id: h.id, h, code, isNew, fs: "beam", fc: cardColor(h) };
  edh.value = code; edSync(); edf.srcdoc = withShim(code); hreset();
  edb.classList.remove("pv");
  $$(".edtabs button").forEach(x => x.classList.toggle("on", x.dataset.ed === "code"));
  edb.hidden = false; document.body.style.overflow = "hidden"; document.documentElement.classList.add("edo"); vvFit();
}
function closeEditor() { document.documentElement.classList.remove("edo"); edb.classList.remove("hc"); $("#edfb").hidden = true; edb.hidden = true; edf.srcdoc = ""; document.body.style.overflow = ""; }
$("#edx").onclick = async () => { if (await ask("Çıkarsan kaydedilmemiş değişiklikler kaybolacak. Çıkılsın mı?", "Çık")) closeEditor(); };

$("#eds").onclick = async () => {
  const e = ctx.ed, code = edh.value;
  if (!code.trim()) return toast("HTML gerekli.");
  if (code.length > 900000) return toast("HTML çok büyük (en fazla ~900 KB).");
  const mm = await askMeta(e.mt ?? e.h.title ?? "", e.md ?? e.h.desc ?? "", e.fs, e.fc); if (!mm) return;
  e.mt = mm.t; e.md = mm.d; e.fs = mm.fs; e.fc = mm.fc; const t = mm.t, d = mm.d;
  try {
    if (e.isNew) {
      const ref = doc(collection(db, "htmls")), w = writeBatch(db);
      w.set(ref, { title: t, desc: d, by: ctx.uid, byName: ctx.name, status: canFree() ? "approved" : "pending", createdAt: serverTimestamp(), ...(e.fs ? { fs: e.fs, fc: e.fc } : {}) });
      w.set(doc(db, "htmlBodies", ref.id), { html: code, by: ctx.uid });
      await w.commit();
      if (!canFree()) notify("html_pending", { detail: t });
      closeEditor(); location.hash = "#/mine";
      if (canFree()) toast("Yayınlandı."); else await inform("HTML admin onayına gönderildi. Güvenlik için paylaşılan her HTML ve her düzenleme admin onayından geçer. Onaylı bir içeriğin sonradan gizlice değiştirilip diğer kullanıcılara zararlı kod gösterilmesini önlemek için böyle yapıyoruz. Onaylanana kadar başkaları göremez.");
      return;
    }
    const ch = t !== e.h.title || d !== (e.h.desc || "") || code !== e.code;
    const fchg = e.fs !== (e.h.fs || "") || (e.fs && e.fc !== cardColor(e.h));
    const st = fchg ? { fs: e.fs, fc: e.fc } : {};
    if (ch || fchg) {
      const w = writeBatch(db);
      if (ch) {
        w.update(doc(db, "htmls", e.id), { title: t, desc: d, ...(canFree() ? {} : { status: "pending" }), ...st });
        w.update(doc(db, "htmlBodies", e.id), { html: code });
      } else w.update(doc(db, "htmls", e.id), st);
      await w.commit();
      if (ch && !canFree()) notify("html_pending", { detail: t });
    }
    closeEditor();
    if (ch && !canFree()) await inform("Düzenlemen kaydedildi ve tekrar admin onayına gönderildi. Güvenlik için paylaşılan her HTML ve her düzenleme admin onayından geçer. Onaylanana kadar başkaları göremez."); else toast("Kaydedildi.");
  } catch (x) { toast(trError(x)); }
};

/* Spam, profil, notlar, arama, admin veri */
const lastT = {};
const spam = (k, gap, txt = "") => {
  const n = Date.now(), l = lastT[k] || { t: 0, x: "" };
  if (n - l.t < gap || (txt && txt === l.x)) { toast("Çok hızlı veya aynı mesaj. Biraz bekle."); return true; }
  lastT[k] = { t: n, x: txt };
  return false;
};

async function changePassword(cur, nw) {
  const u = auth.currentUser;
  await reauthenticateWithCredential(u, EmailAuthProvider.credential(u.email, cur));
  await updatePassword(u, nw);
}

const vbSvg = (z = 16) => `<svg viewBox="0 0 24 24" width="${z}" height="${z}" fill="${PAL[1]}" aria-label="Onaylı Hesap" style="vertical-align:${typeof z === "string" ? "-.19em" : "-3px"};margin-left:${typeof z === "string" ? ".19em" : "3px"}"><g><path d="M22.25 12c0-1.43-.88-2.67-2.19-3.34.46-1.39.2-2.9-.81-3.91s-2.52-1.27-3.91-.81c-.66-1.31-1.91-2.19-3.34-2.19s-2.67.88-3.33 2.19c-1.4-.46-2.91-.2-3.92.81s-1.26 2.52-.8 3.91c-1.31.67-2.2 1.91-2.2 3.34s.89 2.67 2.2 3.34c-.46 1.39-.21 2.9.8 3.91s2.52 1.26 3.91.81c.67 1.31 1.91 2.19 3.34 2.19s2.68-.88 3.34-2.19c1.39.45 2.9.2 3.91-.81s1.27-2.52.81-3.91c1.31-.67 2.19-1.91 2.19-3.34zm-11.71 4.2L6.8 12.46l1.41-1.42 2.26 2.26 4.8-5.23 1.47 1.36-6.2 6.77z"></path></g></svg>`;
const vb = (uid, z) => uid === ADMIN_UID || (ctx.S?.badges || []).includes(uid) ? vbSvg(z) : "";
const avPh = uid => { const p = ctx.S?.profiles?.[uid]?.photoURL; return /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+\/=]+$/.test(p || "") ? p : ""; };
const avHtml = (uid, name, cls = "av") => {
  const ph = avPh(uid), L = ph ? "" : esc((name || "?").charAt(0).toUpperCase());
  return `<span class="${cls}" style="${ph ? `background:url('${ph}') center/cover` : "background:rgba(255,255,255,.12);color:#fff"}">${L}</span>`;
};
function toAvatar(file) {
  return new Promise((res, rej) => {
    const img = new Image(), u = URL.createObjectURL(file);
    img.onload = () => {
      const S = 160, c = document.createElement("canvas"); c.width = c.height = S;
      const m = Math.min(img.width, img.height);
      c.getContext("2d").drawImage(img, (img.width - m) / 2, (img.height - m) / 2, m, m, 0, 0, S, S);
      URL.revokeObjectURL(u); res(c.toDataURL("image/jpeg", .82));
    };
    img.onerror = () => rej(new Error("Görsel okunamadı."));
    img.src = u;
  });
}
const avatar = () => `<button class="avbtn" type="button" data-a="avpick" aria-label="Profil fotoğrafı">${avHtml(ctx.uid, ctx.name, "avbig")}</button><p class="muted" style="margin:0 0 12px;font-size:12px">Fotoğraf eklemek için simgeye dokun.</p>${avPh(ctx.uid) ? '<button type="button" class="btn-ghost sm" data-a="avrm" style="margin-bottom:14px">Fotoğrafı kaldır</button>' : ""}<input id="avf" type="file" accept="image/*" hidden>`;
home.addEventListener("change", async e => {
  if (e.target.id !== "avf" || !e.target.files[0]) return;
  try { await setDoc(doc(db, "profiles", ctx.uid), { photoURL: await toAvatar(e.target.files[0]) }); toast("Fotoğraf kaydedildi."); }
  catch (x) { toast(trError(x)); }
});
function avatarUpd() {
  const h = $("#hav"); if (h) h.innerHTML = avHtml(ctx.uid, ctx.name, "av hv");
}

function homeGrid() {
  const S = ctx.S, t = ctx.tab, q = (ctx.q || "").toLowerCase();
  let l = t === "favs" ? S.htmls.filter(h => S.prefs.favs.includes(h.id)) : S.htmls;
  if (q) l = l.filter(h => (h.title + " " + (h.desc || "")).toLowerCase().includes(q));
  return l.length
    ? `<div class="grid">${[...l].sort((a, b) => S.prefs.pins.includes(b.id) - S.prefs.pins.includes(a.id)).map(hcard).join("")}</div>`
    : empty();
}

function notesList() {
  const l = ctx.S.notes.filter(n => !n.deleted).sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0) || ms(b.updatedAt) - ms(a.updatedAt));
  return l.length ? l.map(n => `<div class="row2${n.pinned ? " np" : ""}"><div><b>${n.pinned ? "📌 " : ""}${esc(n.title || "Başlıksız")}</b><small class="nt">${esc(n.text)}</small><small>${fmt(n.updatedAt)}</small></div><div class="btns"><button data-a="npin" data-id="${n.id}">${n.pinned ? "Sabiti kaldır" : "Sabitle"}</button><button data-a="nedit" data-id="${n.id}">Düzenle</button><button data-a="ndel" data-id="${n.id}">Sil</button></div></div>`).join("") : empty();
}

PAGES.home = () => `<input id="sq" class="sq" type="text" inputmode="search" enterkeyhint="search" name="hsq" placeholder="HTML ara..." value="${esc(ctx.q || "")}" autocomplete="off" autocapitalize="none" spellcheck="false" data-lpignore="true" data-1p-ignore data-bwignore="true" data-form-type="other"><div class="stabs">${TABS.map(([k, n]) => `<button data-t="${k}" class="${k === ctx.tab ? "on" : ""}">${n}</button>`).join("")}</div><div id="hg">${homeGrid()}</div>`;

PAGES.notes = () => `<form id="nf" class="addf"><input id="nt" placeholder="Başlık (isteğe bağlı)" maxlength="80"><textarea id="nx" placeholder="Notunu yaz..." maxlength="2000" style="height:120px"></textarea><p class="err" id="e-nf"></p><button class="btn2" type="submit"><span class="lbl">${ctx.nid ? "Güncelle" : "Not Ekle"}</span><i class="spin"></i></button></form><h3 class="sh">Notlarım</h3><div id="nl">${notesList()}</div>`;

PAGES.settings = () => {
  return `<div class="sets"><section class="scard"><h3 class="sh"><i class="si"><svg class="ic" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg></i>Şifre değiştir</h3><form id="pwf" class="addf"><label class="lb" for="pw0">Mevcut şifre</label><input id="pw0" type="password" placeholder="Mevcut şifre" autocomplete="current-password"><label class="lb" for="pw1">Yeni şifre</label><input id="pw1" type="password" placeholder="Yeni şifre" autocomplete="new-password"><label class="lb" for="pw2">Yeni şifre tekrar</label><input id="pw2" type="password" placeholder="Yeni şifre tekrar" autocomplete="new-password"><p class="err" id="e-pw"></p><button class="btn2" type="submit"><span class="lbl">Şifreyi Değiştir</span><i class="spin"></i></button></form></section><section class="scard"><h3 class="sh"><i class="si red"><svg class="ic" viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/></svg></i>Hesabı sil</h3><form id="dlf" class="addf"><p class="muted">Hesabın kalıcı olarak silinir. HTML'lerin ve notların silinmiş olarak işaretlenir, işlem kayıtları adminde kalır.</p><label class="lb" for="dpw">Şifren</label><input id="dpw" type="password" placeholder="Şifreni gir" autocomplete="current-password"><p class="err" id="e-dl"></p><button class="btn2" type="submit"><span class="lbl">Hesabımı Sil</span><i class="spin"></i></button></form></section><section class="scard"><h3 class="sh"><i class="si"><svg class="ic" viewBox="0 0 24 24"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/></svg></i>Gizlilik</h3><button class="btn-ghost" data-kvkk type="button">Aydınlatma Metni (KVKK) <span>›</span></button></section></div>`;
};


const profHead = p => { const S = ctx.S; return `<h2 class="pnm">${esc(p.fullName || ctx.name)}${vb(ctx.uid, 26)}</h2>${p.bio ? `<p class="pbi">${esc(p.bio)}</p>` : ""}<div class="pst"><div><b>${S.mine.length}</b><span>HTML</span></div><div><b>${S.likes.filter(l => S.mine.some(m => m.id === l.htmlId)).length}</b><span>Beğeni</span></div><div><b>${S.prefs.favs.length}</b><span>Favori</span></div></div>`; };
PAGES.profile = () => {
  const p = ctx.prof || {};
  return `<div class="pcard phc">${avatar()}${profHead(p)}<form id="pf" class="addf"><label class="lb" for="pfn">Ad Soyad</label><input id="pfn" placeholder="Ad Soyad" maxlength="60" value="${esc(p.fullName)}"><label class="lb" for="pun">Kullanıcı adı</label><input id="pun" placeholder="Kullanıcı adı" maxlength="20" value="${esc(ctx.name)}" autocomplete="off" autocapitalize="none">${isFake(ctx.email) ? `<label class="lb" for="pem">E-posta</label><input id="pem" type="email" placeholder="E-posta${p.mailExempt ? "" : " (paylaşılan HTML için zorunlu)"}" maxlength="80" value="${esc(p.contactEmail)}">` : ""}<label class="lb" for="pbio">Biyografi</label><textarea id="pbio" placeholder="Biyografi" maxlength="300">${esc(p.bio)}</textarea><p class="err" id="e-pf"></p><button class="btn2" type="submit"><span class="lbl">Kaydet</span><i class="spin"></i></button></form><p class="muted">Giriş: ${esc(isFake(ctx.email) ? ctx.name : ctx.email)}</p></div>`;
};

home.addEventListener("input", e => {
  if (e.target.id === "sq") { ctx.q = e.target.value; $("#hg").innerHTML = homeGrid(); }
});

const homeClick3 = async e => {
  const b = e.target.closest("[data-a]");
  if (!b) return;
  const d = b.dataset, id = d.id, S = ctx.S;
  try {
    if (d.a === "trace") {
      const t = $("#trin").value, out = $("#trout"), users = ctx.S.users, found = [];
      const bits = [...t].filter(c => c === "\u200b" || c === "\u200c").map(c => c === "\u200c" ? 1 : 0);
      for (let i = 0; i + 224 <= bits.length; i += 224) {
        const uid = String.fromCharCode(...Array.from({ length: 28 }, (_, k) => parseInt(bits.slice(i + k * 8, i + k * 8 + 8).join(""), 2)));
        if (!found.includes(uid)) found.push(uid);
      }
      const m = t.match(/name="x-viewer"\s+content="([^"]+)"/); if (m && !found.includes(m[1])) found.push(m[1]);
      const nm = id => { const u = users.find(x => x.id === id); return u ? `${esc(u.username)}${u.fullName ? " (" + esc(u.fullName) + ")" : ""}` : "Kayıtlı kullanıcı bulunamadı (silinmiş olabilir)"; };
      let h = found.map(id => `<div class="row2"><div><b>${nm(id)}</b><small>Kimlik: ${esc(id)}</small></div></div>`).join("");
      const vis = [...t.matchAll(/([^\n·<>]{2,40}?) · (\d{1,2}\.\d{1,2}\.\d{4})/g)].map(x => x[1].trim() + " · " + x[2]);
      if (vis.length) h += `<h3 class="sh">Görünür filigran</h3>` + [...new Set(vis)].map(v => `<div class="row2"><div><b>${esc(v)}</b></div></div>`).join("");
      out.innerHTML = h || '<p class="empty">İz bulunamadı. (Kopyalarken gizli karakterler silinmiş olabilir; kaynak HTML dosyasını yapıştırmayı dene.)</p>';
    }
    if (d.a === "avpick") $("#avf").click();
    if (d.a === "avrm") await deleteDoc(doc(db, "profiles", ctx.uid));
    if (d.a === "vtog" && ctx.admin) { const b = ctx.S.badges || []; await setDoc(doc(db, "settings", "badges"), { uids: b.includes(d.id) ? b.filter(x => x !== d.id) : [...b, d.id] }, { merge: true }); }
    if (d.a === "npin") { const n = S.notes.find(x => x.id === id); await updateDoc(doc(db, "notes", id), { pinned: !n.pinned }); }
    if (d.a === "nedit") { const n = S.notes.find(x => x.id === id); ctx.nid = id; render(); $("#nt").value = n.title || ""; $("#nx").value = n.text; scrollTo(0, 0); }
    if (d.a === "ndel" && await ask("Bu not silinsin mi?", "Sil")) { await updateDoc(doc(db, "notes", id), { deleted: true, deletedAt: serverTimestamp() }); }
    if (d.a === "andel") { await deleteDoc(doc(db, "announcements", id)); }
    if (d.a === "del") {
      const h = [...S.htmls, ...S.mine].find(x => x.id === id);
      if (h && await ask("Bu HTML ve tüm yorum, beğeni, istekleri kalıcı olarak silinsin mi?", "Sil")) { await wipeHtml(id); toast("Silindi."); }
    }
    if (d.a === "dl") {
      const bd = await getDoc(doc(db, "htmlBodies", id));
      if (!bd.exists()) return toast("İçerik bulunamadı.");
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([bd.data().html], { type: "text/html" }));
      a.download = (d.n || id).replace(/[^\w\-]+/g, "_") + ".html";
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    }
    if (d.a === "ddel" && await ask("Kalıcı olarak silinsin mi? Veritabanından tamamen kaldırılır.", "Sil")) {
      if (d.k === "htmls") await wipeHtml(id); else await deleteDoc(doc(db, d.k, id));
      toast("Silindi.");
    }
    if (d.a === "pclr" && await ask("Bu kullanıcının profil geçmişi silinsin mi?", "Sil")) {
      for (const i of ids(ctx.du || "all")) await delCol(collection(db, "profileHistory", i, "items")); if (ctx.dv) ctx.dv.prof = []; render();
    }
  } catch (x) { toast(trError(x)); }
};

function openAdminChat(id) {
  ctx.ct = id; ctx.cmsgs = [];
  ctx.cmu?.();
  if (id) {
    ctx.cmu = onSnapshot(query(collection(db, "chats", id, "msgs"), orderBy("ts")), s => { ctx.cmsgs = s.docs.map(x => ({ id: x.id, ...x.data() })); rf(); $("#adl")?.scrollTo(0, 1e9); }, () => {});
    setDoc(doc(db, "chats", id), { adminUnread: 0 }, { merge: true }).catch(() => {});
  }
  render();
}
home.addEventListener("change", async e => {
  if (e.target.id === "mu" && e.target.value) return openAdminChat(e.target.value);
  if (e.target.id !== "du") return;
  ctx.du = e.target.value || "all"; loadProf(); render();
});

async function syncName(uid, nm) {
  let ok = true;
  for (const [c, f, k] of [["htmls", "by", "byName"], ["comments", "uid", "name"], ["access", "uid", "name"]]) {
    try {
      const q = await getDocs(query(collection(db, c), where(f, "==", uid)));
      const rows = q.docs.filter(d => d.data()[k] !== nm);
      for (let i = 0; i < rows.length; i += 400) { const w = writeBatch(db); rows.slice(i, i + 400).forEach(d => w.update(d.ref, { [k]: nm })); await w.commit(); }
    } catch { ok = false; }
  }
  try { await updateDoc(doc(db, "chats", uid), { name: nm }); } catch {}
  return ok;
}

const homeSubmit3 = async e => {
  const f = e.target.id;
  if (!["pf", "pwf", "dlf", "nf", "anf"].includes(f)) return;
  e.preventDefault();
  try {
    if (f === "pf") {
      const n = { fullName: $("#pfn").value.trim(), username: $("#pun").value.trim(), contactEmail: $("#pem") ? $("#pem").value.trim().toLowerCase() : (ctx.prof.contactEmail || ""), bio: $("#pbio").value.trim() };
      if (!/^[\p{L}\p{N}_.]{3,20}$/u.test(n.username)) return setErr("pf", "Kullanıcı adı 3-20 karakter olmalı (harf, rakam, _ ve .).");
      if (n.contactEmail && !okMail(n.contactEmail)) return setErr("pf", "Geçersiz e-posta.");
      setErr("pf");
      const o = { ...ctx.prof, username: ctx.name }, ch = Object.keys(n).filter(k => (o[k] || "") !== n[k]);
      if (!ch.length) return toast("Değişiklik yok.");
      let sent = false;
      if (ch.includes("contactEmail") && n.contactEmail && isFake(auth.currentUser.email)) {
        const u0 = auth.currentUser;
        try { await verifyBeforeUpdateEmail(u0, n.contactEmail); sent = true; }
        catch (x) {
          if (x.code !== "auth/requires-recent-login") return setErr("pf", trError(x));
          const pw = await askPass("Güvenlik için mevcut şifreni gir. Onay bağlantısı " + n.contactEmail + " adresine gönderilecek.");
          if (!pw) return;
          try { await reauthenticateWithCredential(u0, EmailAuthProvider.credential(u0.email, pw)); await verifyBeforeUpdateEmail(u0, n.contactEmail); sent = true; }
          catch (y) { return setErr("pf", y.code === "auth/invalid-credential" || y.code === "auth/wrong-password" ? "Şifre hatalı." : trError(y)); }
        }
        setDoc(doc(db, "usernames", slug(ctx.name)), { uid: ctx.uid, email: n.contactEmail }).catch(() => {});
      }
      if (ch.includes("username") && slug(n.username) !== slug(ctx.name)) {
        const t = await getDoc(doc(db, "usernames", slug(n.username))).catch(() => null);
        if (t?.exists() && t.data().uid !== ctx.uid) return setErr("pf", "Bu kullanıcı adı kullanılıyor.");
        const u1 = auth.currentUser, ne = slug(n.username) + MAILDOM;
        if (isFake(u1.email)) {
          try { await updateEmail(u1, ne); }
          catch (x) {
            if (x.code === "auth/requires-recent-login") {
              const pw = await askPass("Kullanıcı adını değiştirmek için mevcut şifreni gir.");
              if (!pw) return;
              try { await reauthenticateWithCredential(u1, EmailAuthProvider.credential(u1.email, pw)); await updateEmail(u1, ne); }
              catch (y) {
                if (y.code === "auth/invalid-credential" || y.code === "auth/wrong-password") return setErr("pf", "Şifre hatalı.");
                if (y.code !== "auth/operation-not-allowed") return setErr("pf", trError(y));
              }
            } else if (x.code !== "auth/operation-not-allowed") return setErr("pf", trError(x));
          }
        }
      }
      let synced = true;
      const w = writeBatch(db);
      w.update(doc(db, "users", ctx.uid), Object.fromEntries(ch.map(k => [k, n[k]])));
      ch.forEach(k => w.set(doc(collection(db, "profileHistory", ctx.uid, "items")), { field: k, old: o[k] || "", new: n[k], ts: serverTimestamp() }));
      await w.commit();
      if (ch.includes("username")) {
        await updateProfile(auth.currentUser, { displayName: n.username });
        const ok = slug(ctx.name), nk = slug(n.username);
        if (ok !== nk) {
          await setDoc(doc(db, "usernames", nk), { uid: ctx.uid, email: auth.currentUser.email });
          deleteDoc(doc(db, "usernames", ok)).catch(() => {});
        }
        ctx.name = n.username;
        synced = await syncName(ctx.uid, n.username);
      }
      Object.assign(ctx.prof, Object.fromEntries(ch.map(k => [k, n[k]])));
      $("#hname").textContent = ctx.name; avatarUpd(); render();
      toast(sent ? "Onay bağlantısı e-postana gönderildi." : synced ? "Profil kaydedildi." : "Profil kaydedildi; eski paylaşım ve yorumlardaki ad güncellenemedi.");
      if (sent) setErr("pf", "Onay e-postası " + n.contactEmail + " adresine gönderildi. Gelen kutunu ve spam klasörünü kontrol et.", true);
    }
    if (f === "pwf") {
      const a = $("#pw0").value, b = $("#pw1").value, c = $("#pw2").value;
      setErr("pw");
      if (!a) return setErr("pw", "Mevcut şifreni gir.");
      if (b.length < 8) return setErr("pw", "Yeni şifre en az 8 karakter olmalı.");
      if (b !== c) return setErr("pw", "Şifreler eşleşmiyor.");
      try { await changePassword(a, b); $("#pwf").reset(); toast("Şifre değiştirildi."); }
      catch (x) { setErr("pw", x.code === "auth/invalid-credential" || x.code === "auth/wrong-password" ? "Mevcut şifre hatalı." : trError(x)); }
    }
    if (f === "dlf") {
      const pw = $("#dpw").value;
      setErr("dl");
      if (!pw) return setErr("dl", "Şifreni gir.");
      if (!await ask("Hesabın silinsin mi?", "Devam")) return;
      if (!await ask("Son uyarı: hesabın kalıcı olarak silinecek ve geri alınamaz. Emin misin?", "Hesabı Sil")) return;
      try {
        const u = auth.currentUser, S = ctx.S, gone = { deleted: true, deletedAt: serverTimestamp() };
        await reauthenticateWithCredential(u, EmailAuthProvider.credential(u.email, pw));
        const refs = [...S.mine.map(h => doc(db, "htmls", h.id)), ...S.notes.filter(n => !n.deleted).map(n => doc(db, "notes", n.id))];
        for (let i = 0; i < refs.length; i += 400) { const w = writeBatch(db); refs.slice(i, i + 400).forEach(r => w.update(r, gone)); await w.commit(); }
        await deleteDoc(doc(db, "prefs", ctx.uid)).catch(() => {});
        await deleteDoc(doc(db, "profiles", ctx.uid)).catch(() => {});
        await updateDoc(doc(db, "users", ctx.uid), { selfDeleted: true, selfDeletedAt: serverTimestamp() });
        await deleteUser(u);
      } catch (x) { setErr("dl", x.code === "auth/invalid-credential" || x.code === "auth/wrong-password" ? "Şifre hatalı." : trError(x)); }
    }
    if (f === "nf") {
      const t = $("#nt").value.trim(), x = $("#nx").value.trim();
      if (!x) return setErr("nf", "Not boş olamaz.");
      setErr("nf");
      if (ctx.nid) { await updateDoc(doc(db, "notes", ctx.nid), { title: t, text: x, updatedAt: serverTimestamp() }); ctx.nid = null; }
      else { await addDoc(collection(db, "notes"), { uid: ctx.uid, title: t, text: x, pinned: false, deleted: false, createdAt: serverTimestamp(), updatedAt: serverTimestamp() }); }
      render();
    }
    if (f === "anf" && ctx.admin) {
      const x = $("#anx").value.trim();
      if (!x) return;
      await addDoc(collection(db, "announcements"), { text: x, by: ctx.uid, ts: serverTimestamp() });
      $("#anx").value = "";
      toast("Duyuru gönderildi.");
    }
  } catch (x) { toast(trError(x)); }
};
home.addEventListener("submit", async e => { await homeSubmit1(e); await homeSubmit2(e); await homeSubmit3(e); });

$("#edel").onclick = async () => {
  if (!await ask(ctx.admin ? "Bu HTML ve tüm yorum, beğeni, istekleri kalıcı olarak silinsin mi?" : "Bu HTML silinsin mi? Admin arşivinde saklanır.", "Sil")) return;
  try {
    if (ctx.admin) await wipeHtml(ctx.ed.id); else await updateDoc(doc(db, "htmls", ctx.ed.id), { deleted: true, deletedAt: serverTimestamp() });
    closeEditor(); toast("Silindi.");
  } catch (x) { toast(trError(x)); }
};

const homeClick4 = async e => {
  const b = e.target.closest("[data-a]");
  if (!b) return;
  const d = b.dataset;
  try {
    if (d.a === "chclear" && await ask("Sohbet senin ekranından temizlensin mi? Admin mesajları görmeye devam eder.", "Temizle")) await setDoc(doc(db, "chats", ctx.uid), { uid: ctx.uid, userClearedAt: Date.now() }, { merge: true });
    if (d.a === "mdel" && ctx.admin) await deleteDoc(doc(db, "chats", ctx.ct, "msgs", d.id));
    if (d.a === "cdelall" && ctx.admin && ctx.ct && await ask("Bu sohbet veritabanından tamamen silinsin mi?", "Sil")) {
      const w = writeBatch(db);
      ctx.cmsgs.forEach(m => w.delete(doc(db, "chats", ctx.ct, "msgs", m.id)));
      w.delete(doc(db, "chats", ctx.ct));
      await w.commit();
      ctx.cmu?.(); ctx.cmu = null; ctx.ct = ""; ctx.cmsgs = [];
      render();
    }
  } catch (x) { toast(trError(x)); }
};
home.addEventListener("click", async e => { await homeClick1(e); await homeClick2(e); await homeClick3(e); await homeClick4(e); });
function askPass(msg) {
  return new Promise(res => {
    const d = $("#dlg"), y = $("#dlgy"), n = $("#dlgn"), p = $("#dlgp");
    $("#dlgt").textContent = msg; p.value = ""; p.hidden = false; y.textContent = "Devam"; d.hidden = false;
    const end = v => { d.hidden = true; p.hidden = true; y.onclick = n.onclick = d.onclick = p.onkeydown = null; res(v); };
    y.onclick = () => end(p.value || null); n.onclick = () => end(null);
    d.onclick = e => { if (e.target === d) end(null); };
    p.onkeydown = e => { if (e.key === "Enter") { e.preventDefault(); end(p.value || null); } };
    p.focus();
  });
}
function inform(msg) {
  return new Promise(res => {
    const d = $("#dlg"), y = $("#dlgy"), n = $("#dlgn");
    $("#dlgt").textContent = msg; y.textContent = "Tamam"; n.hidden = true; d.hidden = false;
    const end = () => { d.hidden = true; n.hidden = false; y.onclick = d.onclick = null; res(); };
    y.onclick = end; d.onclick = e => { if (e.target === d) end(); };
  });
}
function askMeta(t, d, fs0, fc0) {
  return new Promise(res => {
    const dl = $("#dlg"), y = $("#dlgy"), n = $("#dlgn"), a = dl.querySelector(".dlga");
    const i = document.createElement("input"), x = document.createElement("textarea");
    i.className = "sq"; i.maxLength = 80; i.placeholder = "Başlık"; i.value = t; i.style.margin = "0 0 10px";
    x.className = "sq"; x.maxLength = 200; x.placeholder = "Açıklama"; x.value = d; x.style.cssText = "margin:0 0 16px;height:120px;padding:12px 16px;border-radius:18px;resize:vertical;max-width:none";
    let fs = "beam", fc = fc0 || PAL[0];
    const w = document.createElement("div"), pal = document.createElement("div");
    w.style.cssText = "margin:0 0 16px;display:flex;flex-direction:column;gap:10px;align-items:center";
    pal.style.cssText = "display:flex;flex-wrap:wrap;gap:6px;justify-content:center";
    const dr = () => { pal.innerHTML = PAL.map(c => `<button type="button" class="sw${c === fc ? " on" : ""}" data-c="${c}" style="background:${c}" aria-label="${c}"></button>`).join(""); };
    pal.onclick = e => { const b = e.target.closest("[data-c]"); if (b) { fc = b.dataset.c; dr(); } };
    dr(); w.append(pal);
    a.before(i, x, w); $("#dlgt").textContent = "Başlık ve açıklama"; y.textContent = "Kaydet"; dl.hidden = false;
    const end = v => { dl.hidden = true; i.remove(); x.remove(); w.remove(); y.onclick = n.onclick = dl.onclick = null; res(v); };
    y.onclick = () => { if (!i.value.trim()) return toast("Başlık gerekli."); end({ t: i.value.trim(), d: x.value.trim(), fs, fc }); };
    n.onclick = () => end(null); dl.onclick = e => { if (e.target === dl) end(null); };
    i.focus();
  });
}
function ask(msg, ok = "Evet") {
  return new Promise(res => {
    const d = $("#dlg"), y = $("#dlgy"), n = $("#dlgn");
    $("#dlgt").textContent = msg; y.textContent = ok; d.hidden = false;
    const end = v => { d.hidden = true; y.onclick = n.onclick = d.onclick = null; res(v); };
    y.onclick = () => end(true); n.onclick = () => end(false);
    d.onclick = e => { if (e.target === d) end(false); };
    y.focus();
  });
}
const beat = () => { if (ctx.uid && !document.hidden) updateDoc(doc(db, "users", ctx.uid), { lastSeen: serverTimestamp() }).catch(() => {}); };
setInterval(beat, 180000);
document.addEventListener("visibilitychange", beat);
addEventListener("hashchange", route);
$("#collapse").onclick = () => shell.classList.toggle("collapsed");
$("#burger").onclick = () => shell.classList.add("open");
$("#scrim").onclick = () => shell.classList.remove("open");
$("#bell").onclick = e => {
  e.stopPropagation();
  const n = $("#notif"); n.hidden = !n.hidden;
  if (!n.hidden && !ctx.admin && ctx.S.ann.some(a => ms(a.ts) > (ctx.S.prefs.annSeen || 0))) setDoc(doc(db, "prefs", ctx.uid), { annSeen: Date.now() }, { merge: true }).catch(() => {});
};
const docClick3 = e => { if (!e.target.closest("#notif")) $("#notif").hidden = true; };
document.addEventListener("click", async e => { await docClick1(e); await docClick2(e); await docClick3(e); });

startSession(({ screen, user, data }) => {
  if (screen === "verify") $("#vmail").textContent = user.email;
  if (screen === "pending") $('[data-view="pending"] .sub').textContent = data?.violationAt ? "Güvenlik ihlali nedeniyle hesabın tekrar admin onayına alındı. Onaylandığında içeri girebilirsin." : "Kaydın admine bildirildi. Onaylandığında otomatik olarak içeri alınacaksın.";
  if (screen === "home") buildHome(user, data); else clearHome();
  show(screen);
  if (screen === "auth" && goneMsg) { setErr("form", goneMsg); goneMsg = ""; }
  splash.classList.add("off");
});

(() => {
  let t;
  addEventListener("scroll", () => {
    document.body.classList.add("sc");
    clearTimeout(t);
    t = setTimeout(() => document.body.classList.remove("sc"), 180);
  }, { passive: true });
})();

// @## MÜZİK BAŞLANGIÇ
(() => {
  const m = new Audio("MSA.mp3");
  m.preload = "auto";
  document.addEventListener("click", e => {
    if (e.target.closest("#submit-wrap .btn, .flogo")) { m.currentTime = 0; m.play().catch(() => {}); }
  }, true);
})();
// @## MÜZİK BİTİŞ
