/**
 * ============================================================
 *  auth.js — Autenticación OAuth 2.0 / OpenID Connect con Google
 *  Flujo: Google Identity Services (GIS) — 100% frontend
 *  Basado en: github.com/SantiDev11/ReservasJavaScript
 * ============================================================
 *
 * Requisitos:
 * 1. Crear proyecto en https://console.cloud.google.com/
 * 2. Crear credenciales OAuth 2.0 (ID de cliente de OAuth -> Aplicación web)
 * 3. Agregar orígenes autorizados (ej: http://localhost:5500)
 * 4. Copiar el Client ID en CONFIG.CLIENT_ID
 *
 * NOTA: El client_secret NUNCA debe estar en el frontend.
 * Este flujo usa GIS que entrega directamente un ID Token (JWT).
 * ============================================================
 */

window.GoogleAuth = (function () {
  "use strict";

  /* ============================================================
     1. CONFIGURACIÓN
     ============================================================ */
  const CONFIG = {
    CLIENT_ID: "61510338551-29nagua32pgrm0j3ckjo6b3d550jkcgl.apps.googleusercontent.com",
    GIS_SRC: "https://accounts.google.com/gsi/client",
    TOKENINFO_URL: "https://oauth2.googleapis.com/tokeninfo",
    SCOPES: "openid email profile",
    SESSION_KEY: "googleAuthSession",
    SESSION_TTL: 8 * 60 * 60 * 1000, // 8 horas
    CLOCK_SKEW_SECONDS: 300,
    VALID_ISSUERS: ["https://accounts.google.com", "accounts.google.com"],
    PLACEHOLDER_CLIENT_ID: "TU_CLIENT_ID.apps.googleusercontent.com"
  };

  /* ============================================================
     2. ESTADO INTERNO
     ============================================================ */
  let onLoginSuccess = null;
  let onLoginError = null;
  let currentSession = null;
  let gisInitialized = false;

  /* ============================================================
     3. UTILIDADES
     ============================================================ */
  function sanitizePictureUrl(url) {
    const value = String(url || "").trim();
    if (!value) return "";
    try {
      const parsed = new URL(value);
      return parsed.protocol === "https:" ? parsed.href : "";
    } catch {
      return "";
    }
  }

  function isValidEmail(email) {
    return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  function capitalize(s) {
    return s ? s.charAt(0).toUpperCase() + s.slice(1) : "";
  }

  /* ============================================================
     4. CARGAR SCRIPT DE GOOGLE DINÁMICAMENTE
     ============================================================ */
  function loadGisScript() {
    return new Promise((resolve, reject) => {
      if (window.google && window.google.accounts && window.google.accounts.id) {
        resolve();
        return;
      }

      const existing = document.querySelector('script[data-resto-gis="1"]');
      const script = existing || document.createElement("script");

      script.addEventListener("load", () => {
        if (window.google && window.google.accounts && window.google.accounts.id) {
          resolve();
        } else {
          reject(new Error("La librería de Google se cargó sin interfaz de identidad."));
        }
      });

      script.addEventListener("error", () => {
        reject(new Error("No se pudo cargar Google Identity Services."));
      });

      if (!existing) {
        script.src = CONFIG.GIS_SRC;
        script.async = true;
        script.defer = true;
        script.setAttribute("data-resto-gis", "1");
        document.head.appendChild(script);
      }
    });
  }

  /* ============================================================
     5. DECODIFICAR JWT (ID Token)
     ============================================================ */
  function parseJwt(token) {
    try {
      const parts = String(token || "").split(".");
      if (parts.length !== 3) return null;

      const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
      const padded = base64 + "===".slice((base64.length + 3) % 4);
      const jsonPayload = decodeURIComponent(
        atob(padded)
          .split("")
          .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
          .join("")
      );

      const claims = JSON.parse(jsonPayload);
      return claims && typeof claims === "object" && !Array.isArray(claims) ? claims : null;
    } catch {
      return null;
    }
  }

  /* ============================================================
     6. VALIDACIONES BÁSICAS DEL TOKEN (claims)
     ============================================================ */
  function validateJwtClaims(claims) {
    if (!CONFIG.CLIENT_ID || CONFIG.CLIENT_ID.includes("TU_CLIENT_ID")) {
      return { valid: false, reason: "El identificador de cliente de Google no está configurado." };
    }

    if (!claims || typeof claims !== "object") {
      return { valid: false, reason: "El token de Google no se pudo decodificar." };
    }

    if (CONFIG.VALID_ISSUERS.indexOf(String(claims.iss)) === -1) {
      return { valid: false, reason: "El emisor del token es inválido." };
    }

    if (String(claims.aud) !== String(CONFIG.CLIENT_ID).trim()) {
      return { valid: false, reason: "La audiencia del token no coincide con esta aplicación." };
    }

    const now = Math.floor(Date.now() / 1000);
    const exp = Number(claims.exp);

    if (!isFinite(exp) || exp <= 0) {
      return { valid: false, reason: "El token no incluye fecha de expiración." };
    }

    if (exp < now) {
      return { valid: false, reason: "El token de Google ha expirado." };
    }

    const iat = Number(claims.iat);
    if (isFinite(iat) && iat > now + CONFIG.CLOCK_SKEW_SECONDS) {
      return { valid: false, reason: "Fecha de emisión del token en el futuro." };
    }

    if (!claims.sub) {
      return { valid: false, reason: "El token no contiene identificador de usuario." };
    }

    if (!isValidEmail(claims.email)) {
      return { valid: false, reason: "El token no incluye una dirección de correo válida." };
    }

    if (String(claims.email_verified) !== "true") {
      return { valid: false, reason: "El correo de Google no está verificado." };
    }

    return { valid: true, reason: null };
  }

  /* ============================================================
     7. VERIFICACIÓN DE FIRMA CONTRA SERVIDORES DE GOOGLE
     ============================================================ */
  async function verifyIdToken(idToken) {
    try {
      const res = await fetch(
        `${CONFIG.TOKENINFO_URL}?id_token=${encodeURIComponent(idToken)}`
      );

      if (!res.ok) {
        return { valid: false, reason: "Token rechazado por Google." };
      }

      const info = await res.json();

      if (info.aud !== CONFIG.CLIENT_ID) {
        return { valid: false, reason: "El token no fue emitido para esta aplicación." };
      }

      if (String(info.email_verified) !== "true") {
        return { valid: false, reason: "El correo de Google no está verificado." };
      }

      return { valid: true, info };
    } catch {
      return { valid: false, reason: "Error de red al verificar el token." };
    }
  }

  /* ============================================================
     8. GESTIÓN DE SESIONES
     ============================================================ */
  function saveSession(sessionData) {
    try {
      sessionStorage.setItem(CONFIG.SESSION_KEY, JSON.stringify(sessionData));
      return true;
    } catch {
      return false;
    }
  }

  function loadSession() {
    try {
      const raw = sessionStorage.getItem(CONFIG.SESSION_KEY);
      if (!raw) return null;
      const session = JSON.parse(raw);
      if (!session || !session.idToken || !session.expiresAt) return null;
      if (Date.now() > session.expiresAt) {
        sessionStorage.removeItem(CONFIG.SESSION_KEY);
        return null;
      }
      return session;
    } catch {
      return null;
    }
  }

  function clearSession() {
    currentSession = null;
    sessionStorage.removeItem(CONFIG.SESSION_KEY);
  }

  /* ============================================================
     9. CONSTRUIR SESIÓN
     ============================================================ */
  function buildSession(idToken, claims) {
    const tokenExpiresAt = Number(claims.exp) * 1000;
    const ttlExpiresAt = Date.now() + CONFIG.SESSION_TTL;

    return {
      idToken: idToken,
      email: claims.email,
      name: claims.name || claims.email.split("@")[0],
      picture: sanitizePictureUrl(claims.picture),
      loginAt: new Date().toISOString(),
      expiresAt: Math.min(tokenExpiresAt, ttlExpiresAt)
    };
  }

  /* ============================================================
     10. CALLBACK DE GOOGLE AL AUTENTICAR
     ============================================================ */
  async function handleCredentialResponse(response) {
    const idToken = response && response.credential;
    if (!idToken) {
      if (onLoginError) onLoginError("No se recibió credencial de Google.");
      return;
    }

    const claims = parseJwt(idToken);
    const localCheck = validateJwtClaims(claims);

    if (!localCheck.valid) {
      if (onLoginError) onLoginError(localCheck.reason);
      return;
    }

    const verification = await verifyIdToken(idToken);
    if (!verification.valid) {
      if (onLoginError) onLoginError(verification.reason);
      return;
    }

    const session = buildSession(idToken, verification.info);
    if (!saveSession(session)) {
      if (onLoginError) onLoginError("No se pudo guardar la sesión en este navegador.");
      return;
    }

    currentSession = session;

    if (onLoginSuccess) {
      onLoginSuccess({
        email: session.email,
        emailVerified: true,
        name: session.name,
        picture: session.picture,
        sub: verification.info.sub
      });
    }
  }

  /* ============================================================
     11. INICIALIZAR BOTÓN GOOGLE
     ============================================================ */
  async function init({ buttonContainerId, onSuccess, onError, usePrompt = false } = {}) {
    onLoginSuccess = onSuccess || null;
    onLoginError = onError || null;

    function fail(reason) {
      if (onLoginError) onLoginError(reason);
      throw new Error(reason);
    }

    const origin = window.location.origin;

    if (
      origin === "null" ||
      (!location.protocol.startsWith("https") &&
        !origin.startsWith("http://localhost") &&
        !origin.startsWith("http://127.0.0.1"))
    ) {
      fail(
        "Google no permite iniciar sesión desde file://. " +
          "Abre la app por un servidor local (Live Server en VS Code) " +
          "y autoriza ese origen en Google Cloud Console."
      );
      return;
    }

    if (
      CONFIG.CLIENT_ID.includes("TU_CLIENT_ID") ||
      !CONFIG.CLIENT_ID.endsWith("apps.googleusercontent.com")
    ) {
      fail(
        "El Client ID de Google no está configurado. " +
          "Pega tu Client ID real en CONFIG.CLIENT_ID de auth.js."
      );
      return;
    }

    try {
      await loadGisScript();
    } catch (e) {
      fail("No se pudo cargar Google Identity Services. Revisa tu conexión a internet.");
      return;
    }

    try {
      if (!gisInitialized) {
        google.accounts.id.initialize({
          client_id: CONFIG.CLIENT_ID,
          callback: handleCredentialResponse,
          auto_select: false,
          cancel_on_tap_outside: true
        });
        gisInitialized = true;
      }

      if (buttonContainerId) {
        const container = document.getElementById(buttonContainerId);
        if (container) {
          container.innerHTML = "";

          window.google.accounts.id.renderButton(container, {
            theme: 'filled_black',
            size: 'large',
            shape: 'pill',
            text: 'signin_with',
            width: 320,
            logo_alignment: 'left'
          });

          console.info("[GoogleAuth] Botón oficial de Google añadido. Origen actual:", origin);
          console.info(
            "[GoogleAuth] Asegúrate de que este origen esté autorizado en Google Cloud Console -> Credenciales -> Orígenes de JavaScript autorizados."
          );
        }
      }

      if (usePrompt) {
        google.accounts.id.prompt();
      }
    } catch (e) {
      fail(
        "No se pudo dibujar el botón de Google. " +
          "Origen actual: " +
          origin +
          ". Verifica que esté autorizado en Google Cloud Console."
      );
    }
  }

  /* ============================================================
     12. RESTAURAR SESIÓN EXISTENTE
     ============================================================ */
  async function restoreSession() {
    try {
      const session = loadSession();
      if (!session) return null;

      const verification = await verifyIdToken(session.idToken);
      if (!verification.valid) {
        sessionStorage.removeItem(CONFIG.SESSION_KEY);
        currentSession = null;
        return null;
      }

      currentSession = session;
      return {
        email: session.email,
        emailVerified: true,
        name: session.name,
        picture: session.picture,
        sub: verification.info.sub
      };
    } catch {
      return null;
    }
  }

  /* ============================================================
     13. CERRAR SESIÓN
     ============================================================ */
  function logout() {
    currentSession = null;
    sessionStorage.removeItem(CONFIG.SESSION_KEY);

    if (window.google && window.google.accounts && window.google.accounts.id) {
      google.accounts.id.disableAutoSelect();
    }
  }

  /* ============================================================
     14. OBTENER SESIÓN ACTUAL
     ============================================================ */
  function getSession() {
    return currentSession;
  }

  /* ============================================================
     15. API PÚBLICA
     ============================================================ */
  return {
    init,
    restoreSession,
    logout,
    getSession,
    verifyIdToken,
    parseJwt,
    validateJwtClaims,
    CONFIG
  };
})();
