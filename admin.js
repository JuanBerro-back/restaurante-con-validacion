/**
 * admin.js — Lógica principal del panel RestoApp
 * Módulos: Crypto · Store · Validate · Data · Auth · Menu · Views · Modal · Login · Events
 */
"use strict";

(function AppMain() {

  /* ============================================================
     1. CRYPTO — AES-256-GCM por sesión
     ============================================================ */
  const Crypto = (() => {
    const KEY_STORE = 'restoKey';
    let _key = null;

    function bufToB64(buf) {
      const bytes = new Uint8Array(buf);
      let s = '';
      for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function b64ToBuf(b64) {
      const base64 = b64.replace(/-/g, '+').replace(/_/g, '/');
      const pad = base64.length % 4 === 0 ? '' : '='.repeat(4 - base64.length % 4);
      const s = atob(base64 + pad);
      const buf = new Uint8Array(s.length);
      for (let i = 0; i < s.length; i++) buf[i] = s.charCodeAt(i);
      return buf.buffer;
    }

    async function generate() {
      _key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
      const raw = await crypto.subtle.exportKey('raw', _key);
      sessionStorage.setItem(KEY_STORE, bufToB64(raw));
    }

    async function load() {
      const stored = sessionStorage.getItem(KEY_STORE);
      if (!stored) return;
      try {
        const raw = b64ToBuf(stored);
        _key = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
      } catch {
        _key = null;
        sessionStorage.removeItem(KEY_STORE);
      }
    }

    function clear()  { _key = null; sessionStorage.removeItem(KEY_STORE); }
    function hasKey() { return !!_key; }

    async function encrypt(text) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const enc = new TextEncoder().encode(text);
      const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, _key, enc);
      return bufToB64(cipher) + '.' + bufToB64(iv.buffer);
    }

    async function decrypt(encoded) {
      const [dataB64, ivB64] = encoded.split('.');
      if (!dataB64 || !ivB64) throw new Error('Formato inválido');
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(b64ToBuf(ivB64)) },
        _key,
        b64ToBuf(dataB64)
      );
      return new TextDecoder().decode(plain);
    }

    return { generate, load, clear, hasKey, encrypt, decrypt };
  })();

  /* ============================================================
     2. STORAGE SEGURO
     ============================================================ */
  const Store = {
    async set(key, data) {
      if (!Crypto.hasKey()) return;
      try {
        const enc = await Crypto.encrypt(JSON.stringify(data));
        localStorage.setItem(key, enc);
      } catch (e) { console.warn('Store.set', e); }
    },

    async get(key) {
      if (!Crypto.hasKey()) return null;
      try {
        const enc = localStorage.getItem(key);
        if (!enc) return null;
        return JSON.parse(await Crypto.decrypt(enc));
      } catch { return null; }
    }
  };

  /* ============================================================
     3. VALIDACIÓN / SANITIZACIÓN
     ============================================================ */
  const Validate = {
    sanitize(str) {
      if (typeof str !== 'string') return '';
      return str.replace(/[<>]/g, '').replace(/['";\/\\]/g, '').trim();
    },

    isText(str) {
      if (typeof str !== 'string' || str.length === 0 || str.length > 100) return false;
      return /^[a-zA-Z0-9áéíóúÁÉÍÓÚñÑüÜ\s\-_,.:]+$/.test(str);
    },

    int(v, fallback = null) {
      const n = parseInt(v, 10);
      return Number.isInteger(n) ? n : fallback;
    },

    escHtml(str) {
      if (str == null) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }
  };

  /* ============================================================
     4. DATOS POR DEFECTO
     ============================================================ */
  const DEFAULT_MESAS = Array.from({ length: 8 }, (_, i) => ({
    id: i + 1, numero: i + 1, estado: 'disponible', reservaId: null
  }));

  const DEFAULT_PLATOS = [
    { id: 1, nombre: 'Ceviche',               precio: 12.5 },
    { id: 2, nombre: 'Lomo saltado',           precio: 15.0 },
    { id: 3, nombre: 'Arroz con pollo',        precio: 11.0 },
    { id: 4, nombre: 'Pasta al pesto',         precio: 10.5 },
    { id: 5, nombre: 'Ensalada mediterránea',  precio: 8.0  },
    { id: 6, nombre: 'Sopa de mariscos',       precio: 14.0 },
    { id: 7, nombre: 'Parrillada',             precio: 22.0 },
    { id: 8, nombre: 'Flan de coco',           precio: 6.5  }
  ];

  function defaultData() {
    return {
      mesas:     JSON.parse(JSON.stringify(DEFAULT_MESAS)),
      platos:    JSON.parse(JSON.stringify(DEFAULT_PLATOS)),
      reservas:  [],
      pedidos:   [],
      despachos: []
    };
  }

  /* ============================================================
     5. ESTADO GLOBAL
     ============================================================ */
  let currentUser = null;
  let data        = null;
  let currentView = 'dashboard';

  /* ============================================================
     6. REFERENCIAS DOM
     ============================================================ */
  const $ = (id) => document.getElementById(id);
  const dom = {
    sidebar:         $('sidebar'),
    menuContainer:   $('menuContainer'),
    pageContent:     $('pageContent'),
    viewTitle:       $('viewTitle'),
    roleBadge:       $('roleBadge'),
    userNameDisplay: $('userNameDisplay'),
    userRoleDisplay: $('userRoleDisplay'),
    userAvatar:      $('userAvatar'),
    modalOverlay:    $('modalOverlay'),
    modalBody:       $('modalBody'),
    modalCloseBtn:   $('modalCloseBtn'),
  };

  /* ============================================================
     7. DATA — Cargar / Guardar
     ============================================================ */
  async function loadData() {
    let stored = await Store.get('restoData');
    if (!stored) {
      data = defaultData();
      await saveData();
    } else {
      data = stored;
      if (!data.mesas    || !data.mesas.length)    data.mesas    = JSON.parse(JSON.stringify(DEFAULT_MESAS));
      if (!data.platos   || !data.platos.length)   data.platos   = JSON.parse(JSON.stringify(DEFAULT_PLATOS));
      if (!data.reservas)  data.reservas  = [];
      if (!data.pedidos)   data.pedidos   = [];
      if (!data.despachos) data.despachos = [];
    }
    data.mesas.forEach(m => { if (!m.estado) m.estado = 'disponible'; });
  }

  async function saveData() { await Store.set('restoData', data); }

  /* ============================================================
     8. AUTENTICACIÓN — Mapeo email → rol
     ============================================================ */
  // Edita este objeto para asignar roles concretos por correo
  const ROLE_BY_EMAIL = {
    // 'gerente@example.com': 'administrador',
    // 'mesero@example.com':  'mesero',
  };

  function roleFromEmail(email) {
    const e = (email || '').toLowerCase();
    if (ROLE_BY_EMAIL[e]) return ROLE_BY_EMAIL[e];
    if (e.endsWith('@gmail.com') || e.endsWith('@googlemail.com')) return 'administrador';
    return 'mesero';
  }

  /* ============================================================
     9. MENÚ POR ROL
     ============================================================ */
  const MENU_ITEMS = [
    { id: 'dashboard', label: 'Panel',     icon: 'fa-chart-pie',      roles: ['administrador','mesero','cocina','despacho'] },
    { id: 'mesas',     label: 'Mesas',     icon: 'fa-chair',          roles: ['administrador','mesero'] },
    { id: 'reservas',  label: 'Reservas',  icon: 'fa-calendar-check', roles: ['administrador','mesero'] },
    { id: 'pedidos',   label: 'Pedidos',   icon: 'fa-clipboard-list', roles: ['administrador','mesero'] },
    { id: 'cocina',    label: 'Cocina',    icon: 'fa-fire',           roles: ['administrador','cocina'] },
    { id: 'despachos', label: 'Despachos', icon: 'fa-truck',          roles: ['administrador','despacho'] },
    { id: 'usuarios',  label: 'Usuarios',  icon: 'fa-users-cog',      roles: ['administrador'] }
  ];

  function buildMenu() {
    if (!currentUser) return;
    const items = MENU_ITEMS.filter(m => m.roles.includes(currentUser.rol));
    dom.menuContainer.innerHTML = items.map(m =>
      `<div class="menu-item" data-view="${m.id}" role="button" tabindex="0">
         <i class="fas ${Validate.escHtml(m.icon)}"></i>
         <span>${Validate.escHtml(m.label)}</span>
       </div>`
    ).join('');

    dom.menuContainer.querySelectorAll('.menu-item').forEach(el => {
      el.addEventListener('click', () => {
        renderView(el.dataset.view);
        if (window.innerWidth < 820) dom.sidebar.classList.remove('open');
      });
      el.addEventListener('keydown', e => { if (e.key === 'Enter') el.click(); });
    });
    highlightMenu();
  }

  function highlightMenu() {
    dom.menuContainer.querySelectorAll('.menu-item').forEach(el =>
      el.classList.toggle('active', el.dataset.view === currentView)
    );
  }

  /* ============================================================
     10. ROUTER DE VISTAS
     ============================================================ */
  const VIEW_TITLES = {
    dashboard: 'Panel de control',
    mesas:     'Gestión de mesas',
    reservas:  'Reservas',
    pedidos:   'Pedidos',
    cocina:    'Cola de cocina',
    despachos: 'Despachos',
    usuarios:  'Administración'
  };

  function renderView(viewId) {
    if (!currentUser) { showLogin(); return; }
    currentView = viewId;
    dom.viewTitle.textContent = VIEW_TITLES[viewId] || 'Panel';
    dom.roleBadge.textContent = capitalize(currentUser.rol);
    highlightMenu();

    const views = { dashboard: viewDashboard, mesas: viewMesas, reservas: viewReservas,
                    pedidos: viewPedidos, cocina: viewCocina, despachos: viewDespachos, usuarios: viewUsuarios };
    const renderer = views[viewId];
    dom.pageContent.innerHTML = renderer
      ? `<div class="fade-in">${renderer()}</div>`
      : '<p>Vista no disponible</p>';
  }

  function capitalize(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : ''; }

  /* ============================================================
     11. VISTAS
     ============================================================ */

  function viewDashboard() {
    const hoy          = new Date().toISOString().slice(0, 10);
    const reservasHoy  = data.reservas.filter(r => r.fecha === hoy).length;
    const pendientes   = data.pedidos.flatMap(p => p.platos || []).filter(pl => ['pendiente','preparacion'].includes(pl.estado)).length;
    const despachosAct = data.despachos.filter(d => ['ruta','pendiente'].includes(d.estado)).length;
    const mesasOcup    = data.mesas.filter(m => m.estado === 'ocupada').length;

    return `
      <div class="stats-grid">
        <div class="stat-card"><i class="fas fa-calendar-day"></i><div class="stat-info"><h4>Reservas hoy</h4><span>${reservasHoy}</span></div></div>
        <div class="stat-card"><i class="fas fa-utensils"></i><div class="stat-info"><h4>Platos pendientes</h4><span>${pendientes}</span></div></div>
        <div class="stat-card"><i class="fas fa-truck"></i><div class="stat-info"><h4>Despachos activos</h4><span>${despachosAct}</span></div></div>
        <div class="stat-card"><i class="fas fa-chair"></i><div class="stat-info"><h4>Mesas ocupadas</h4><span>${mesasOcup}</span></div></div>
      </div>
      <div class="card">
        <div class="card-header"><h3>👋 Bienvenido</h3></div>
        <p>Hola, <strong>${Validate.escHtml(currentUser.username)}</strong>.
           Rol: <span class="badge badge-reservada">${Validate.escHtml(currentUser.rol)}</span></p>
      </div>`;
  }

  function viewMesas() {
    const items = data.mesas.map(m => {
      const cls   = ['disponible','reservada','ocupada'].includes(m.estado) ? m.estado : 'disponible';
      const label = { disponible:'Disponible', reservada:'Reservada', ocupada:'Ocupada' }[cls];
      return `<div class="mesa-item ${cls}">
        <div class="mesa-num">Mesa ${Validate.escHtml(m.numero)}</div>
        <div class="mesa-estado">${label}</div>
      </div>`;
    }).join('');
    return `<div class="card">
      <div class="card-header"><h3>Estado de mesas</h3></div>
      <div class="mesas-grid">${items}</div>
    </div>`;
  }

  function viewReservas() {
    const filas = data.reservas.length
      ? data.reservas.map(r => {
          const mesa = data.mesas.find(m => m.id === r.mesaId);
          return `<tr>
            <td>Mesa ${Validate.escHtml(mesa ? mesa.numero : '?')}</td>
            <td>${Validate.escHtml(r.fecha)}</td>
            <td>${Validate.escHtml(r.hora)}</td>
            <td>${Validate.escHtml(r.personas)}</td>
            <td><span class="badge badge-reservada">Reservada</span></td>
          </tr>`;
        }).join('')
      : '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);">Sin reservas registradas</td></tr>';

    return `<div class="card">
      <div class="card-header">
        <h3>Reservas</h3>
        <button class="btn btn-primary" onclick="App.openModal('reserva')"><i class="fas fa-plus"></i> Nueva</button>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Mesa</th><th>Fecha</th><th>Hora</th><th>Personas</th><th>Estado</th></tr></thead>
          <tbody>${filas}</tbody>
        </table>
      </div>
    </div>`;
  }

  function viewPedidos() {
    const filas = data.pedidos.length
      ? data.pedidos.map(p => {
          const mesa  = data.mesas.find(m => m.id === p.mesaId);
          const plStr = (p.platos || []).map(pl =>
            `${Validate.escHtml(pl.nombre)} <span class="badge">${Validate.escHtml(pl.estado)}</span>`
          ).join(' ');
          const pid = Validate.int(p.id, 0);
          return `<tr>
            <td>Mesa ${Validate.escHtml(mesa ? mesa.numero : '?')}</td>
            <td>${plStr || '—'}</td>
            <td><span class="badge">${Validate.escHtml(p.estado || 'activo')}</span></td>
            <td><button class="btn btn-sm btn-outline" onclick="App.openModal('pedido',${pid})">Editar</button></td>
          </tr>`;
        }).join('')
      : '<tr><td colspan="4" style="text-align:center;color:var(--text-muted);">Sin pedidos</td></tr>';

    return `<div class="card">
      <div class="card-header">
        <h3>Pedidos</h3>
        <button class="btn btn-primary" onclick="App.openModal('pedido')"><i class="fas fa-plus"></i> Nuevo pedido</button>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Mesa</th><th>Platos</th><th>Estado</th><th>Acción</th></tr></thead>
          <tbody>${filas}</tbody>
        </table>
      </div>
    </div>`;
  }

  function viewCocina() {
    const all = data.pedidos.flatMap(p =>
      (p.platos || []).map((pl, i) => ({ ...pl, pedidoId: p.id, innerIdx: i }))
    );
    const pendientes  = all.filter(pl => pl.estado === 'pendiente');
    const preparacion = all.filter(pl => pl.estado === 'preparacion');

    function filasCocina(lista, estadoBtn, textoBtn, cssBtn) {
      if (!lista.length) return '<tr><td colspan="3" style="text-align:center;color:var(--text-muted);">Sin platos</td></tr>';
      return lista.map(pl => {
        const pid = Validate.int(pl.pedidoId, 0);
        const idx = Validate.int(pl.innerIdx, 0);
        return `<tr>
          <td>${Validate.escHtml(pl.nombre)}</td>
          <td>#${Validate.escHtml(pl.pedidoId)}</td>
          <td><button class="btn btn-sm ${cssBtn}" onclick="App.cocinaAction(${pid},${idx},'${estadoBtn}')">${textoBtn}</button></td>
        </tr>`;
      }).join('');
    }

    return `
      <div class="card">
        <div class="card-header"><h3>🕐 Pendientes</h3></div>
        <div class="table-wrap"><table>
          <thead><tr><th>Plato</th><th>Pedido</th><th>Acción</th></tr></thead>
          <tbody>${filasCocina(pendientes, 'preparacion', 'Preparar', 'btn-primary')}</tbody>
        </table></div>
      </div>
      <div class="card">
        <div class="card-header"><h3>🔥 En preparación</h3></div>
        <div class="table-wrap"><table>
          <thead><tr><th>Plato</th><th>Pedido</th><th>Acción</th></tr></thead>
          <tbody>${filasCocina(preparacion, 'listo', 'Listo', 'btn-success')}</tbody>
        </table></div>
      </div>`;
  }

  function viewDespachos() {
    const estados = ['pendiente','ruta','entregado'];
    const filas = data.despachos.length
      ? data.despachos.map(d => {
          const pStr   = (d.platos || []).map(Validate.escHtml).join(', ');
          const est    = estados.includes(d.estado) ? d.estado : 'pendiente';
          const did    = Validate.int(d.id, 0);
          const accion = est === 'pendiente'
            ? `<button class="btn btn-sm btn-primary" onclick="App.despachoAction(${did},'ruta')">En ruta</button>`
            : est === 'ruta'
            ? `<button class="btn btn-sm btn-success" onclick="App.despachoAction(${did},'entregado')">Entregar</button>`
            : '—';
          return `<tr>
            <td>#${Validate.escHtml(d.pedidoId)}</td>
            <td>${pStr || '—'}</td>
            <td><span class="badge badge-${est}">${est}</span></td>
            <td>${accion}</td>
          </tr>`;
        }).join('')
      : '<tr><td colspan="4" style="text-align:center;color:var(--text-muted);">Sin despachos</td></tr>';

    return `<div class="card">
      <div class="card-header">
        <h3>Despachos</h3>
        <button class="btn btn-primary" onclick="App.openModal('despacho')"><i class="fas fa-plus"></i> Nuevo despacho</button>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Pedido</th><th>Platos</th><th>Estado</th><th>Acción</th></tr></thead>
          <tbody>${filas}</tbody>
        </table>
      </div>
    </div>`;
  }

  function viewUsuarios() {
    return `<div class="card">
      <div class="card-header"><h3>⚙️ Administración</h3></div>
      <p>Autenticación OAuth 2.0 / OpenID Connect con Google.<br>
         El rol se asigna según el correo en el objeto <code>ROLE_BY_EMAIL</code> de <code>admin.js</code>.</p>
      <div style="margin-top:20px;">
        <button class="btn btn-danger" onclick="App.resetData()">
          <i class="fas fa-undo-alt"></i> Resetear datos demo
        </button>
      </div>
    </div>`;
  }

  /* ============================================================
     12. MODAL
     ============================================================ */
  let platosTemp = [];

  window.App = {};

  App.openModal = function(type, id) {
    let html = '';

    if (type === 'reserva') {
      const optMesas = data.mesas
        .filter(m => m.estado === 'disponible')
        .map(m => `<option value="${Validate.int(m.id,0)}">Mesa ${Validate.escHtml(m.numero)}</option>`)
        .join('');
      html = `<h3 id="modalTitle">Nueva reserva</h3>
        <div class="form-group"><label>Mesa</label><select id="mdMesa">${optMesas}</select></div>
        <div class="form-row">
          <div class="form-group"><label>Fecha</label><input type="date" id="mdFecha" value="${new Date().toISOString().slice(0,10)}"></div>
          <div class="form-group"><label>Hora</label><input type="time" id="mdHora" value="20:00"></div>
        </div>
        <div class="form-group"><label>Personas</label><input type="number" id="mdPersonas" value="2" min="1"></div>
        <button class="btn btn-primary" onclick="App.saveReserva()"><i class="fas fa-check"></i> Guardar</button>`;

    } else if (type === 'pedido') {
      platosTemp = [];
      const pedido = id ? data.pedidos.find(p => p.id === id) : null;
      const mesaId = pedido?.mesaId ?? data.mesas[0]?.id;
      const optMesas = data.mesas
        .map(m => `<option value="${Validate.int(m.id,0)}" ${m.id === mesaId ? 'selected' : ''}>Mesa ${Validate.escHtml(m.numero)}</option>`)
        .join('');
      const optPlatos = data.platos
        .map(p => `<option value="${Validate.int(p.id,0)}">${Validate.escHtml(p.nombre)}</option>`)
        .join('');
      html = `<h3 id="modalTitle">${pedido ? 'Editar' : 'Nuevo'} pedido</h3>
        <div class="form-group"><label>Mesa</label><select id="mdMesaPedido">${optMesas}</select></div>
        <div class="form-group"><label>Agregar plato</label><select id="mdPlatoSel">${optPlatos}</select></div>
        <button class="btn btn-sm btn-outline" onclick="App.addPlato()" style="margin-bottom:12px;">
          <i class="fas fa-plus"></i> Agregar
        </button>
        <div id="platosAgregados" style="min-height:24px;margin-bottom:16px;"></div>
        <button class="btn btn-primary" onclick="App.savePedido(${Validate.int(id, 'null')})"><i class="fas fa-check"></i> Guardar pedido</button>`;

      if (pedido) {
        platosTemp = [...(pedido.platos || [])];
        setTimeout(refreshPlatosUI, 50);
      }

    } else if (type === 'despacho') {
      const candidatos = data.pedidos.filter(p => (p.platos || []).some(pl => pl.estado === 'listo'));
      const optPedidos = candidatos
        .map(p => `<option value="${Validate.int(p.id,0)}">Pedido #${Validate.escHtml(p.id)}</option>`)
        .join('');
      html = `<h3 id="modalTitle">Nuevo despacho</h3>
        <div class="form-group"><label>Pedido</label>
          <select id="mdPedidoDesp">${optPedidos || '<option value="">Sin pedidos listos</option>'}</select>
        </div>
        <button class="btn btn-primary" onclick="App.saveDespacho()"><i class="fas fa-check"></i> Crear despacho</button>`;
    }

    dom.modalBody.innerHTML = html;
    dom.modalOverlay.classList.add('open');
  };

  function closeModal() {
    dom.modalOverlay.classList.remove('open');
    platosTemp = [];
  }

  function refreshPlatosUI() {
    const container = document.getElementById('platosAgregados');
    if (!container) return;
    container.innerHTML = platosTemp.length
      ? platosTemp.map(pl => `<span class="badge" style="margin:3px;">${Validate.escHtml(pl.nombre)}</span>`).join('')
      : '<span style="color:var(--text-muted);font-size:0.8rem;">Sin platos agregados</span>';
  }

  App.addPlato = function() {
    const platoId = Validate.int(document.getElementById('mdPlatoSel').value, -1);
    if (platoId < 0) return;
    const plato = data.platos.find(p => p.id === platoId);
    if (!plato || platosTemp.find(p => p.id === plato.id)) return;
    platosTemp.push({ id: plato.id, nombre: Validate.sanitize(plato.nombre), precio: Number(plato.precio) || 0, estado: 'pendiente' });
    refreshPlatosUI();
  };

  App.saveReserva = async function() {
    const mesaId   = Validate.int(document.getElementById('mdMesa').value, -1);
    const fecha    = Validate.sanitize(document.getElementById('mdFecha').value);
    const hora     = Validate.sanitize(document.getElementById('mdHora').value);
    const personas = Validate.int(document.getElementById('mdPersonas').value, -1);
    if (mesaId < 0 || personas < 1 || !Validate.isText(fecha) || !Validate.isText(hora)) { alert('Datos inválidos'); return; }
    const mesa = data.mesas.find(m => m.id === mesaId && m.estado === 'disponible');
    if (!mesa) { alert('Mesa no disponible'); return; }
    data.reservas.push({ id: Date.now(), mesaId, fecha, hora, personas });
    mesa.estado = 'reservada';
    await saveData(); closeModal(); renderView(currentView);
  };

  App.savePedido = async function(id) {
    const mesaId = Validate.int(document.getElementById('mdMesaPedido').value, -1);
    if (mesaId < 0) { alert('Seleccione mesa'); return; }
    if (!id && platosTemp.length === 0) { alert('Agregue al menos un plato'); return; }
    const mesa = data.mesas.find(m => m.id === mesaId);
    if (!mesa) return;
    if (id) {
      const pid = Validate.int(id, -1);
      const pedido = data.pedidos.find(p => p.id === pid);
      if (pedido && platosTemp.length) pedido.platos = platosTemp;
    } else {
      data.pedidos.push({ id: Date.now(), mesaId, platos: platosTemp, estado: 'activo' });
      mesa.estado = 'ocupada';
    }
    platosTemp = [];
    await saveData(); closeModal(); renderView(currentView);
  };

  App.saveDespacho = async function() {
    const pedidoId = Validate.int(document.getElementById('mdPedidoDesp').value, -1);
    if (pedidoId < 0) return;
    const pedido = data.pedidos.find(p => p.id === pedidoId);
    if (!pedido) return;
    const platos = (pedido.platos || []).filter(pl => pl.estado === 'listo').map(pl => Validate.sanitize(pl.nombre));
    if (!platos.length) { alert('No hay platos listos'); return; }
    data.despachos.push({ id: Date.now(), pedidoId, platos, estado: 'pendiente' });
    await saveData(); closeModal(); renderView(currentView);
  };

  App.cocinaAction = async function(pedidoId, platoIdx, nuevoEstado) {
    pedidoId = Validate.int(pedidoId, -1);
    platoIdx = Validate.int(platoIdx, -1);
    if (!['pendiente','preparacion','listo'].includes(nuevoEstado)) return;
    const pedido = data.pedidos.find(p => p.id === pedidoId);
    if (!pedido || platoIdx < 0 || platoIdx >= (pedido.platos || []).length) return;
    pedido.platos[platoIdx].estado = nuevoEstado;
    await saveData(); renderView(currentView);
  };

  App.despachoAction = async function(despachoId, nuevoEstado) {
    despachoId = Validate.int(despachoId, -1);
    if (!['pendiente','ruta','entregado'].includes(nuevoEstado)) return;
    const d = data.despachos.find(x => x.id === despachoId);
    if (!d) return;
    d.estado = nuevoEstado;
    await saveData(); renderView(currentView);
  };

  App.resetData = async function() {
    if (!confirm('¿Resetear todos los datos a valores demo?')) return;
    data = defaultData();
    await saveData(); renderView(currentView);
  };

  /* ============================================================
     13. PANTALLA DE LOGIN
     ============================================================ */
  function showLogin() {
    const isFile = !window.location.protocol.startsWith('http');
    const origin  = window.location.origin !== 'null' ? window.location.origin : 'file://';

    dom.sidebar.style.display = 'none';
    const mainEl = document.getElementById('mainContent');
    Object.assign(mainEl.style, { marginLeft: '0', display: 'flex', alignItems: 'center', justifyContent: 'center' });

    dom.pageContent.innerHTML = `
      <div class="login-card">
        <div class="login-logo">
          <div class="ball"></div>
          <span style="font-size:1.6rem;font-weight:700;color:var(--text-primary);">RestoApp</span>
        </div>
        <p class="subtitle">Sistema de Reservas · Acceso con Google</p>
        <div id="googleSignInDiv" style="display:flex;justify-content:center;"></div>
        <p class="login-hint" id="loginHint"></p>
        ${isFile
          ? `<div class="alert-warning"><strong>⚠ Google OAuth no funciona con <code>file://</code></strong><br>
               Usa un servidor local (Live Server en VS Code) o sube el proyecto a GitHub Pages.</div>`
          : `<div class="alert-info"><strong>Origen:</strong> <code>${Validate.escHtml(origin)}</code><br>
               Si el botón no aparece, autoriza este origen en Google Cloud Console → Credenciales → <em>Orígenes autorizados</em>.</div>`}
      </div>`;

    dom.viewTitle.textContent = 'Inicio de sesión';

    if (window.GoogleAuth) {
      GoogleAuth.init({
        buttonContainerId: 'googleSignInDiv',
        onSuccess: user => doGoogleLogin(user),
        onError: msg => {
          const hint = document.getElementById('loginHint');
          if (hint) hint.innerHTML = `<span style="color:var(--danger);">⚠ ${Validate.escHtml(msg)}</span>`;
        }
      }).catch(e => {
        const hint = document.getElementById('loginHint');
        if (hint) hint.textContent = 'Error: ' + (e?.message || e);
      });
    } else {
      const hint = document.getElementById('loginHint');
      if (hint) hint.innerHTML = 'Google OAuth no disponible. Verifica que <code>google-oauth.js</code> se cargue correctamente.';
    }
  }

  /* ============================================================
     14. LOGIN CON GOOGLE
     ============================================================ */
  async function doGoogleLogin(user) {
    if (user.emailVerified === false) {
      alert('Tu correo de Google no está verificado. Acceso denegado.');
      return;
    }
    const email = (user.email || '').toLowerCase();
    currentUser = {
      username:     user.name || email.split('@')[0],
      email,
      picture:      user.picture || null,
      rol:          roleFromEmail(email),
      authProvider: 'google'
    };

    try { await Crypto.generate(); } catch (e) { console.warn('Crypto:', e); }
    await loadData();
    sessionStorage.setItem('restoUser', JSON.stringify(currentUser));

    const mainEl = document.getElementById('mainContent');
    dom.sidebar.style.display = '';
    Object.assign(mainEl.style, { marginLeft: '', display: '', alignItems: '', justifyContent: '' });

    updateSidebarUser();
    buildMenu();
    renderView('dashboard');
  }

  function updateSidebarUser() {
    if (!currentUser) return;
    dom.userNameDisplay.textContent = currentUser.username;
    dom.userRoleDisplay.textContent = capitalize(currentUser.rol);
    dom.userAvatar.innerHTML = currentUser.picture
      ? `<img src="${Validate.escHtml(currentUser.picture)}" alt="Avatar">`
      : `<i class="fas fa-user"></i>`;
  }

  /* ============================================================
     15. LOGOUT
     ============================================================ */
  function doLogout() {
    if (window.GoogleAuth && currentUser?.authProvider === 'google') GoogleAuth.logout();
    currentUser = null;
    Crypto.clear();
    sessionStorage.removeItem('restoUser');
    dom.sidebar.classList.remove('open');
    showLogin();
  }

  /* ============================================================
     16. EVENTOS GLOBALES
     ============================================================ */
  dom.modalCloseBtn.addEventListener('click', closeModal);
  dom.modalOverlay.addEventListener('click', e => { if (e.target === dom.modalOverlay) closeModal(); });
  $('logoutBtn').addEventListener('click', doLogout);
  $('hamburgerBtn').addEventListener('click', () => dom.sidebar.classList.toggle('open'));

  /* ============================================================
     17. INIT — Restaurar sesión o mostrar login
     ============================================================ */
  (async function init() {
    const storedUser = sessionStorage.getItem('restoUser');
    if (storedUser) {
      try {
        const u = JSON.parse(storedUser);
        if (u.authProvider === 'google' && window.GoogleAuth) {
          const payload = GoogleAuth.restoreSession();
          if (payload) {
            await Crypto.load();
            currentUser = u;
            await loadData();
            dom.sidebar.style.display = '';
            updateSidebarUser();
            buildMenu();
            renderView('dashboard');
            return;
          }
        }
      } catch { /* sesión corrupta */ }
    }
    Crypto.clear();
    sessionStorage.removeItem('restoUser');
    showLogin();
  })();

})(); // fin AppMain
