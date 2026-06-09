/* ================================================================
   KAWSAY LUMINA — FORM CONTROLLER
   Seguridad: honeypot, time-check, rate-limit, sanitización XSS
   ================================================================ */

"use strict";
"use strict";

// ── FORZAR MODAL OCULTO AL CARGAR ─────────────────────────────
window.addEventListener("load", () => {
  const modal = document.getElementById("modalGracias");
  if (modal) {
    modal.style.display = "none";
    modal.style.visibility = "hidden";
  }
});
// ── CONFIGURACIÓN ──────────────────────────────────────────────
// 🔑 Pega aquí tu endpoint de SheetMonkey (https://sheetmonkey.io)
const ENDPOINT = "https://api.sheetmonkey.io/form/2hsPYnaCJN3vYHXefjjNRd";

const CONFIG = {
  MIN_FILL_SECONDS: 4,    // mínimo tiempo para llenar el form (anti-bot)
  MAX_SUBMITS_PER_SESSION: 3,  // máximo envíos por sesión
  RATE_LIMIT_MS: 60000,   // ms entre envíos (1 minuto)
  MAX_FIELD_LENGTH: 600,  // caracteres máximos por campo
};
// ──────────────────────────────────────────────────────────────

// Estado de seguridad
let submitCount = 0;
let lastSubmitTime = 0;
let isSubmitting = false;

// Campos obligatorios con sus reglas
const REQUIRED_FIELDS = [
  { id: "nombre",      label: "Nombre",      min: 2,  type: "text"  },
  { id: "apellido",    label: "Apellido",     min: 2,  type: "text"  },
  { id: "cedula",      label: "Cédula",       min: 6,  type: "text"  },
  { id: "correo",      label: "Correo",       min: 6,  type: "email" },
  { id: "whatsapp",    label: "WhatsApp",     min: 7,  type: "tel"   },
  { id: "institucion", label: "Institución",  min: 3,  type: "text"  },
  { id: "curso",       label: "Curso",        min: 1,  type: "select"},
];

// ── INICIALIZACIÓN ─────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {

  // Guardar tiempo de carga (anti-bot timing)
  document.getElementById("form_time").value = Date.now();

  // Fecha máxima para fecha de nacimiento = hoy
  const fnac = document.getElementById("fecha_nacimiento");
  if (fnac) fnac.max = new Date().toISOString().split("T")[0];

  // Progress bar
  initProgressBar();

  // Validación en tiempo real (blur)
  REQUIRED_FIELDS.forEach(f => {
    const el = document.getElementById(f.id);
    if (!el) return;
    el.addEventListener("blur", () => validateField(f));
    el.addEventListener("input", () => {
      if (el.classList.contains("invalid")) validateField(f);
      updateProgressBar();
    });
  });

  // Submit
  document.getElementById("registroForm")
    .addEventListener("submit", handleSubmit);
});

// ── PROGRESS BAR ───────────────────────────────────────────────
function initProgressBar() {
  const allFields = document.querySelectorAll(
    "#registroForm input:not([type=hidden]):not([type=checkbox]):not(#hp_website), #registroForm select, #registroForm textarea"
  );
  allFields.forEach(el => {
    el.addEventListener("input", updateProgressBar);
    el.addEventListener("change", updateProgressBar);
  });
}

function updateProgressBar() {
  const requiredEls = REQUIRED_FIELDS.map(f => document.getElementById(f.id)).filter(Boolean);
  const filled = requiredEls.filter(el => el.value.trim().length > 0).length;
  const pct = Math.round((filled / requiredEls.length) * 100);

  const bar = document.getElementById("progressBar");
  const label = document.getElementById("progressLabel");
  if (bar)   bar.style.setProperty("--progress", pct + "%");
  if (label) label.textContent = pct + "% completado";

  // Accesibilidad
  const container = bar?.parentElement;
  if (container) container.setAttribute("aria-valuenow", pct);
}

// ── SANITIZACIÓN (previene XSS) ────────────────────────────────
function sanitize(str) {
  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\//g, "&#x2F;")
    .trim()
    .slice(0, CONFIG.MAX_FIELD_LENGTH);
}

function getValue(id) {
  const el = document.getElementById(id);
  return el ? sanitize(el.value) : "";
}

// ── VALIDACIONES ───────────────────────────────────────────────
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}
function isValidPhone(phone) {
  return /^[0-9\s\-\+]{7,15}$/.test(phone.replace(/\s/g, ""));
}
function isValidText(str, min) {
  return str.trim().length >= min && !/[<>{}]/.test(str);
}

function validateField(fieldDef) {
  const el = document.getElementById(fieldDef.id);
  if (!el) return true;
  const val = el.value.trim();
  let ok = true;
  let msg = "";

  if (!val || val.length < fieldDef.min) {
    ok = false;
    msg = `Ingresa un ${fieldDef.label.toLowerCase()} válido (mínimo ${fieldDef.min} caracteres).`;
  } else if (fieldDef.type === "email" && !isValidEmail(val)) {
    ok = false;
    msg = "Ingresa un correo electrónico válido.";
  } else if (fieldDef.type === "tel" && !isValidPhone(val)) {
    ok = false;
    msg = "Ingresa solo números (7–15 dígitos).";
  } else if (fieldDef.type === "text" && !isValidText(val, fieldDef.min)) {
    ok = false;
    msg = "El texto contiene caracteres no permitidos.";
  }

  const errEl = document.getElementById("error-" + fieldDef.id);
  if (errEl) errEl.textContent = ok ? "" : msg;
  el.classList.toggle("invalid", !ok);
  el.classList.toggle("valid", ok);
  return ok;
}

function validateAll() {
  let valid = true;
  REQUIRED_FIELDS.forEach(f => { if (!validateField(f)) valid = false; });

  const terminos = document.getElementById("terminos");
  if (!terminos.checked) {
    document.getElementById("error-terminos").textContent =
      "Debes aceptar los términos para continuar.";
    valid = false;
  } else {
    document.getElementById("error-terminos").textContent = "";
  }

  return valid;
}

// ── CONTROLES DE SEGURIDAD ─────────────────────────────────────
function securityChecks() {
  // 1. Honeypot — si tiene contenido, es un bot
  const hp = document.getElementById("hp_website").value;
  if (hp && hp.trim() !== "") {
    console.warn("Bot detectado (honeypot).");
    return false;
  }

  // 2. Tiempo mínimo de llenado
  const formTime = parseInt(document.getElementById("form_time").value, 10);
  const elapsed = (Date.now() - formTime) / 1000;
  if (elapsed < CONFIG.MIN_FILL_SECONDS) {
    console.warn("Envío demasiado rápido:", elapsed, "s");
    return false;
  }

  // 3. Rate limiting por sesión
  if (submitCount >= CONFIG.MAX_SUBMITS_PER_SESSION) {
    showGlobalError("Has alcanzado el límite de registros para esta sesión.");
    return false;
  }

  // 4. Rate limiting por tiempo
  if (lastSubmitTime && (Date.now() - lastSubmitTime) < CONFIG.RATE_LIMIT_MS) {
    const secs = Math.ceil((CONFIG.RATE_LIMIT_MS - (Date.now() - lastSubmitTime)) / 1000);
    showGlobalError(`Por favor espera ${secs} segundos antes de enviar de nuevo.`);
    return false;
  }

  return true;
}

function showGlobalError(msg) {
  const el = document.getElementById("globalError");
  if (el) { el.textContent = "⚠️ " + msg; el.style.display = "block"; }
}
function hideGlobalError() {
  const el = document.getElementById("globalError");
  if (el) el.style.display = "none";
}

// ── SUBMIT ─────────────────────────────────────────────────────
async function handleSubmit(e) {
  e.preventDefault();

  if (isSubmitting) return;

  hideGlobalError();

  // Controles de seguridad primero
  if (!securityChecks()) return;

  // Validación de campos
  if (!validateAll()) {
    showGlobalError("Por favor corrige los campos marcados antes de continuar.");
    // Scroll al primer error
    const firstError = document.querySelector(".invalid");
    if (firstError) firstError.scrollIntoView({ behavior: "smooth", block: "center" });
    return;
  }

  // UI: loading
  isSubmitting = true;
  const btn = document.getElementById("btnSubmit");
  btn.disabled = true;
  btn.querySelector(".btn-text").style.display = "none";
  btn.querySelector(".btn-loading").style.display = "inline-flex";

  // Recolectar y sanitizar datos
  const datos = {
    Nombre:          getValue("nombre"),
    Apellido:        getValue("apellido"),
    Cedula:          getValue("cedula"),
    FechaNacimiento: getValue("fecha_nacimiento"),
    Correo:          getValue("correo"),
    WhatsApp:        getValue("indicativo") + " " + getValue("whatsapp"),
    Institucion:     getValue("institucion"),
    NivelEducativo:  getValue("nivel_educativo"),
    Titulo:          getValue("titulo"),
    Curso:           getValue("curso"),
    Modalidad:       getValue("modalidad"),
    Horario:         getValue("horario"),
    FechaRegistro:   new Date().toLocaleString("es-EC", { timeZone: "America/Guayaquil" }),

    // ── ESPACIOS EXTRA — descomenta lo que actives en el HTML ──
    // TelefonoFijo:    getValue("telefono_fijo"),
    // CorreoAlt:       getValue("correo_alt"),
    // Experiencia:     getValue("experiencia"),
    // ComoNosConocio:  getValue("como_entero"),
    // CodigoPromo:     getValue("codigo_promo"),
    // PreguntaExtra1:  getValue("pregunta_extra_1"),
    // PreguntaExtra2:  getValue("pregunta_extra_2"),
    // Observaciones:   getValue("observaciones"),
  };

  try {
    const res = await fetch(ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
      body: JSON.stringify(datos),
      signal: AbortSignal.timeout(12000), // timeout 12s
    });

    if (res.ok) {
      submitCount++;
      lastSubmitTime = Date.now();
      mostrarModal(datos.Nombre + " " + datos.Apellido);
      document.getElementById("registroForm").reset();
      document.getElementById("form_time").value = Date.now();
      updateProgressBar();
      // Limpiar clases de validación
      document.querySelectorAll(".valid, .invalid").forEach(el => {
        el.classList.remove("valid", "invalid");
      });
    } else {
      const errData = await res.json().catch(() => ({}));
      showGlobalError(errData.message || "Error al enviar. Por favor intenta de nuevo.");
    }

  } catch (err) {
    if (err.name === "TimeoutError") {
      showGlobalError("La conexión tardó demasiado. Revisa tu internet e intenta de nuevo.");
    } else {
      showGlobalError("No se pudo conectar. Verifica tu conexión a internet.");
    }
    console.error("Error de envío:", err);
  }

  // Restaurar botón
  isSubmitting = false;
  btn.disabled = false;
  btn.querySelector(".btn-text").style.display = "inline";
  btn.querySelector(".btn-loading").style.display = "none";
}

// ── MODAL ──────────────────────────────────────────────────────
function mostrarModal(nombreCompleto) {
  document.getElementById("nombreRegistrado").textContent = nombreCompleto;
  const modal = document.getElementById("modalGracias");
  modal.removeAttribute("hidden");
  modal.classList.remove("hidden");
  modal.style.display = "flex";
  modal.style.visibility = "visible";
  setTimeout(() => {
    const closeBtn = modal.querySelector(".btn-modal-close");
    if (closeBtn) closeBtn.focus();
  }, 350);
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function cerrarModal() {
  const modal = document.getElementById("modalGracias");
  modal.style.display = "none";
  modal.style.visibility = "hidden";
  modal.setAttribute("hidden", "");
  modal.classList.add("hidden");
  document.getElementById("nombre")?.focus();
}