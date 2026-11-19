// Backend Cloudflare + Supabase con sesiones firmadas, permisos por rol y validaciones.
// Variables (tipo Secret) necesarias en Cloudflare:
//   SUPABASE_URL, SUPABASE_SERVICE_KEY, SESSION_SECRET
// Opcional: DEBUG = 1 (muestra el detalle de los errores internos; no lo dejes activo en produccion)

const enc = encodeURIComponent;
const te = new TextEncoder();
const td = new TextDecoder();

const TZ = 'America/Mexico_City';
const EARLY_MIN = 15;               // minutos antes de la clase en los que el profesor ya puede avisar
const SESSION_COOKIE = 'utn_session';
const SESSION_TTL = 8 * 60 * 60;    // la sesion dura 8 horas
const MAX_FAILS = 5;                // intentos fallidos antes de bloquear
const LOCK_MIN = 10;                // minutos de bloqueo
const DAYS = ['Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado', 'Domingo'];
const ROLES = ['alumno', 'docente', 'admin'];
const GROUP_RE = /^[A-Za-z0-9][A-Za-z0-9 _-]{0,19}$/;
const SUBJECT_RE = /^[\p{L}\p{N} .,()\-]{1,60}$/u;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// ---------------------------------------------------------------- Supabase
async function sb(env, pathAndQuery, { method = 'GET', body, prefer } = {}) {
  const key = env.SUPABASE_SERVICE_KEY;
  if (!key || !env.SUPABASE_URL) {
    throw new Error('Faltan las variables SUPABASE_URL o SUPABASE_SERVICE_KEY en el Worker');
  }
  const headers = { apikey: key, 'Content-Type': 'application/json' };
  // Las llaves JWT clasicas (eyJ...) tambien van en Authorization; las nuevas sb_secret_... no
  if (key.startsWith('eyJ')) headers.Authorization = `Bearer ${key}`;
  if (prefer) headers.Prefer = prefer;

  const base = env.SUPABASE_URL.trim().replace(/\/rest\/v1\/?$/, '').replace(/\/+$/, '');
  const res = await fetch(`${base}/rest/v1/${pathAndQuery}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Supabase ${res.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}

// ---------------------------------------------------------------- Sesiones firmadas (HMAC-SHA256)
function b64urlEncode(bytes) {
  let s = '';
  bytes.forEach(b => { s += String.fromCharCode(b); });
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

function hmacKey(env, usages) {
  return crypto.subtle.importKey('raw', te.encode(env.SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, usages);
}

async function signToken(env, payload) {
  const body = b64urlEncode(te.encode(JSON.stringify(payload)));
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(env, ['sign']), te.encode(body)));
  return `${body}.${b64urlEncode(sig)}`;
}

async function verifyToken(env, token) {
  try {
    const [body, sig] = String(token).split('.');
    if (!body || !sig) return null;
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(env, ['verify']), b64urlDecode(sig), te.encode(body));
    if (!ok) return null;
    const payload = JSON.parse(td.decode(b64urlDecode(body)));
    if (!payload.exp || payload.exp < Date.now() / 1000) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

function getCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

function sessionCookie(token, maxAge) {
  return `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

// Exige una sesion valida y, opcionalmente, uno de los roles indicados
async function requireSession(request, env, roles, { verifyUser = true } = {}) {
  if (!env.SESSION_SECRET) throw new Error('Falta la variable SESSION_SECRET en el Worker');
  const token = getCookie(request, SESSION_COOKIE);
  const session = token ? await verifyToken(env, token) : null;
  if (!session) throw new HttpError(401, 'Sesión no válida o expirada. Inicia sesión de nuevo.');
  if (roles && !roles.includes(session.role)) throw new HttpError(403, 'No tienes permiso para esta acción.');

  // Confirma que el usuario sigue existiendo y conserva su rol (por si lo borraron o le cambiaron el rol)
  if (verifyUser) {
    const rows = await sb(env, `users?select=id,role&id=eq.${Number(session.uid)}&limit=1`);
    if (!rows[0] || rows[0].role !== session.role) {
      throw new HttpError(401, 'Sesión no válida. Inicia sesión de nuevo.');
    }
  }
  return session;
}

// ---------------------------------------------------------------- Bloqueo por intentos fallidos
async function minutesLocked(env, key) {
  const rows = await sb(env, `login_attempts?select=locked_until&key=eq.${enc(key)}&limit=1`);
  const until = rows[0]?.locked_until ? new Date(rows[0].locked_until).getTime() : 0;
  return until > Date.now() ? Math.ceil((until - Date.now()) / 60000) : 0;
}

async function registerFail(env, key) {
  const rows = await sb(env, `login_attempts?select=fails&key=eq.${enc(key)}&limit=1`);
  const fails = (rows[0]?.fails || 0) + 1;
  const lock = fails >= MAX_FAILS;
  await sb(env, 'login_attempts?on_conflict=key', {
    method: 'POST',
    prefer: 'resolution=merge-duplicates',
    body: {
      key,
      fails: lock ? 0 : fails,
      locked_until: lock ? new Date(Date.now() + LOCK_MIN * 60000).toISOString() : null
    }
  });
}

async function clearFails(env, key) {
  await sb(env, `login_attempts?key=eq.${enc(key)}`, { method: 'DELETE' });
}

// ---------------------------------------------------------------- Validaciones
async function readJson(request) {
  try {
    return await request.json();
  } catch (e) {
    throw new HttpError(400, 'Solicitud no válida.');
  }
}

const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

function validateUser(b, creating) {
  const username = typeof b.username === 'string' ? b.username.trim() : '';
  if (!/^[A-Za-z0-9._-]{3,30}$/.test(username)) {
    throw new HttpError(400, 'El usuario debe tener de 3 a 30 caracteres (letras, números, punto, guion o guion bajo).');
  }
  if (!ROLES.includes(b.role)) throw new HttpError(400, 'Rol no válido.');

  const nombre = str(b.nombre, 60);
  const appPaterno = str(b.appPaterno, 60);
  if (!nombre || !appPaterno) throw new HttpError(400, 'El nombre y el apellido paterno son obligatorios.');

  let grupo = 'N/A';
  if (b.role === 'alumno') {
    grupo = str(b.grupo, 20);
    if (!GROUP_RE.test(grupo)) throw new HttpError(400, 'Selecciona un grupo válido para el alumno.');
  }

  const value = {
    username,
    role: b.role,
    nombre,
    app_paterno: appPaterno,
    name: `${nombre} ${appPaterno}`,
    grupo,
    extra: { appMaterno: str(b.appMaterno, 60), turno: str(b.turno, 20) }
  };

  const hasPassword = typeof b.password === 'string' && b.password !== '';
  if (hasPassword) {
    if (b.password.length < 8 || b.password.length > 100) {
      throw new HttpError(400, 'La contraseña debe tener entre 8 y 100 caracteres.');
    }
    value.password = b.password; // un trigger en Supabase la guarda cifrada (bcrypt)
  } else if (creating) {
    throw new HttpError(400, 'La contraseña es obligatoria (mínimo 8 caracteres).');
  }
  return value;
}

function validateGroups(input) {
  let groups = input || {};
  if (Array.isArray(groups)) {
    const obj = {};
    groups.forEach(n => { obj[n] = { subjects: [] }; });
    groups = obj;
  }
  if (typeof groups !== 'object') throw new HttpError(400, 'Datos de grupos no válidos.');

  const clean = {};
  for (const [name, data] of Object.entries(groups)) {
    if (!GROUP_RE.test(name)) {
      throw new HttpError(400, `Nombre de grupo no válido: "${name}". Usa letras, números, espacios, guion o guion bajo (máx. 20).`);
    }
    const subjects = Array.isArray(data?.subjects) ? data.subjects : [];
    if (subjects.length > 40) throw new HttpError(400, 'Demasiadas materias en un grupo.');
    subjects.forEach(s => {
      if (typeof s !== 'string' || !SUBJECT_RE.test(s)) {
        throw new HttpError(400, `Nombre de materia no válido: "${s}". Usa solo letras, números, espacios y . , ( ) -`);
      }
    });
    clean[name] = { subjects };
  }
  return clean;
}

function validateSchedule(group, schedule) {
  if (!GROUP_RE.test(String(group || ''))) throw new HttpError(400, 'Grupo no válido.');
  if (!Array.isArray(schedule) || schedule.length > 100) throw new HttpError(400, 'Horario no válido.');
  return schedule.map(it => {
    const range = parseRange(it?.time);
    if (!DAYS.includes(it?.day) || !range || range.end <= range.start || !str(it.subject, 60)) {
      throw new HttpError(400, 'Hay filas del horario con datos no válidos (día, hora o materia).');
    }
    return { day: it.day, time: str(it.time, 20), subject: str(it.subject, 60), teacher: str(it.teacher, 120) };
  });
}

function dupCheck(err) {
  if (String(err.message).includes('23505')) throw new HttpError(409, 'Ese nombre de usuario ya existe.');
  throw err;
}

// ---------------------------------------------------------------- Formatos de respuesta
// Nunca se devuelve la contrasena (ni cifrada)
function formatUser(u) {
  return {
    ...(u.extra || {}),
    id: u.id,
    username: u.username,
    name: u.name,
    nombre: u.nombre,
    appPaterno: u.app_paterno,
    role: u.role,
    grupo: u.grupo
  };
}

function formatNotification(n) {
  return {
    id: n.id,
    teacherName: n.teacher_name,
    classroom: n.classroom,
    message: n.message,
    group: n.group_name,
    subject: n.subject,
    timestamp: new Date(n.created_at).toLocaleTimeString('es-MX', { timeZone: TZ })
  };
}

// ---------------------------------------------------------------- Clase actual del profesor segun el horario
// Minusculas y sin acentos, para comparar "Miércoles" con "miercoles"
const norm = s => String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').trim().toLowerCase();

function nowInMexico() {
  const parts = new Intl.DateTimeFormat('es-MX', {
    timeZone: TZ, weekday: 'long', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'
  }).formatToParts(new Date());
  const get = t => parts.find(p => p.type === t)?.value;
  return { day: norm(get('weekday')), minutes: Number(get('hour')) * 60 + Number(get('minute')) };
}

// "07:00 - 09:00" -> { start: 420, end: 540 } (en minutos)
function parseRange(str) {
  const m = String(str || '').match(/(\d{1,2}):(\d{2}).*?(\d{1,2}):(\d{2})/);
  if (!m) return null;
  return { start: Number(m[1]) * 60 + Number(m[2]), end: Number(m[3]) * 60 + Number(m[4]) };
}

async function findCurrentClasses(env, teacherName) {
  const { day, minutes } = nowInMexico();
  const rows = await sb(env, 'schedules?select=group_name,schedule');
  const found = [];

  for (const row of rows) {
    for (const item of row.schedule || []) {
      if (norm(item.teacher) !== norm(teacherName)) continue;
      if (norm(item.day) !== day) continue;
      const r = parseRange(item.time);
      if (!r) continue;
      if (minutes >= r.start - EARLY_MIN && minutes < r.end) {
        found.push({ group: row.group_name, subject: item.subject, time: item.time, start: r.start });
      }
    }
  }

  // Si hay una clase que aun no empieza (clases seguidas), se prefiere la proxima
  const upcoming = found.filter(c => minutes < c.start);
  return upcoming.length ? upcoming : found;
}

// ---------------------------------------------------------------- Asistencia
const ATTENDANCE_STATUS = ['presente', 'retardo', 'falta'];
const collator = new Intl.Collator('es', { sensitivity: 'base' });

// Fecha de hoy (AAAA-MM-DD) en hora de Mexico
function todayMexico() {
  return new Intl.DateTimeFormat('en-CA', { timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());
}

function studentRow(u) {
  return {
    id: u.id,
    nombre: u.nombre || u.name || '',
    appPaterno: u.app_paterno || '',
    appMaterno: u.extra?.appMaterno || ''
  };
}

// Orden alfabetico: apellido paterno, apellido materno y nombre (ignora acentos y mayusculas)
function sortStudents(list) {
  return list.sort((a, b) =>
    collator.compare(a.appPaterno, b.appPaterno) ||
    collator.compare(a.appMaterno, b.appMaterno) ||
    collator.compare(a.nombre, b.nombre));
}

// El profesor solo puede tomar lista del grupo con el que tiene clase en este momento
async function classForGroup(env, teacherName, group) {
  const classes = await findCurrentClasses(env, teacherName);
  const cls = classes.find(c => c.group === group);
  if (!cls) throw new HttpError(409, 'No tienes una clase en curso con ese grupo en este momento.');
  return cls;
}

function groupStudents(env, group) {
  return sb(env, `users?select=id,name,nombre,app_paterno,extra&role=eq.alumno&grupo=eq.${enc(group)}`);
}

// ---------------------------------------------------------------- Rutas
// Devuelve una Response para rutas /api/*, o null si la ruta no es de la API
async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '');
  const method = request.method;

  if (!path.startsWith('/api/')) return null;

  const jsonRes = (data, status = 200, headers = {}) =>
    new Response(JSON.stringify(data), {
      status,
      headers: {
        'Content-Type': 'application/json;charset=UTF-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        ...headers
      }
    });

  try {
    // Proteccion basica contra peticiones desde otros sitios (CSRF)
    if (!['GET', 'HEAD'].includes(method)) {
      const origin = request.headers.get('Origin');
      if (origin && origin !== url.origin) throw new HttpError(403, 'Origen no permitido.');
    }

    // ===== Sesion =====
    if (path === '/api/login' && method === 'POST') {
      if (!env.SESSION_SECRET) throw new Error('Falta la variable SESSION_SECRET en el Worker');
      const b = await readJson(request);
      const username = typeof b.username === 'string' ? b.username.trim() : '';
      const password = typeof b.password === 'string' ? b.password : '';
      const bad = () => jsonRes({ success: false, message: 'Usuario o contraseña incorrectos' }, 401);

      if (!username || !password || username.length > 50 || password.length > 100) return bad();

      const key = username.toLowerCase();
      const wait = await minutesLocked(env, key);
      if (wait > 0) {
        return jsonRes({
          success: false,
          message: `Demasiados intentos fallidos. Intenta de nuevo en ${wait} minuto(s).`
        }, 429);
      }

      // La comparacion de contrasena (bcrypt) ocurre dentro de Supabase
      const rows = await sb(env, 'rpc/verify_user', {
        method: 'POST',
        body: { p_username: username, p_password: password }
      });
      const user = rows && rows[0];
      if (!user) {
        await registerFail(env, key);
        return bad();
      }
      await clearFails(env, key);

      const name = user.name || `${user.nombre || ''} ${user.app_paterno || ''}`.trim();
      const grupo = user.grupo || 'N/A';
      const token = await signToken(env, {
        uid: user.id,
        username: user.username,
        name,
        role: user.role,
        grupo,
        exp: Math.floor(Date.now() / 1000) + SESSION_TTL
      });
      return jsonRes(
        { success: true, user: { name, role: user.role, grupo } },
        200,
        { 'Set-Cookie': sessionCookie(token, SESSION_TTL) }
      );
    }

    if (path === '/api/logout' && method === 'POST') {
      return jsonRes({ success: true }, 200, { 'Set-Cookie': sessionCookie('', 0) });
    }

    if (path === '/api/me' && method === 'GET') {
      const s = await requireSession(request, env, null);
      return jsonRes({ success: true, user: { name: s.name, role: s.role, grupo: s.grupo } });
    }

    // ===== Usuarios (solo administrador) =====
    if (path === '/api/admin/users' && method === 'GET') {
      await requireSession(request, env, ['admin']);
      const rows = await sb(env, 'users?select=id,username,name,nombre,app_paterno,role,grupo,extra&order=id');
      return jsonRes({ users: rows.map(formatUser) });
    }

    if (path === '/api/admin/users' && method === 'POST') {
      await requireSession(request, env, ['admin']);
      const v = validateUser(await readJson(request), true);
      let rows;
      try {
        rows = await sb(env, 'users', { method: 'POST', prefer: 'return=representation', body: v });
      } catch (e) {
        dupCheck(e);
      }
      return jsonRes({ success: true, user: formatUser(rows[0]) });
    }

    if (path.startsWith('/api/admin/users/') && method === 'PUT') {
      const s = await requireSession(request, env, ['admin']);
      const id = Number(path.split('/').pop());
      if (!Number.isInteger(id)) throw new HttpError(400, 'Identificador no válido.');
      const v = validateUser(await readJson(request), false);
      if (id === s.uid && v.role !== 'admin') {
        throw new HttpError(400, 'No puedes quitarte a ti mismo el rol de administrador.');
      }
      let rows;
      try {
        rows = await sb(env, `users?id=eq.${id}`, { method: 'PATCH', prefer: 'return=representation', body: v });
      } catch (e) {
        dupCheck(e);
      }
      if (!rows.length) throw new HttpError(404, 'Usuario no encontrado.');
      return jsonRes({ success: true, user: formatUser(rows[0]) });
    }

    if (path.startsWith('/api/admin/users/') && method === 'DELETE') {
      const s = await requireSession(request, env, ['admin']);
      const id = Number(path.split('/').pop());
      if (!Number.isInteger(id)) throw new HttpError(400, 'Identificador no válido.');
      if (id === s.uid) throw new HttpError(400, 'No puedes eliminar tu propia cuenta.');
      await sb(env, `users?id=eq.${id}`, { method: 'DELETE' });
      return jsonRes({ success: true });
    }

    // ===== Grupos =====
    if (path === '/api/admin/groups' && method === 'GET') {
      await requireSession(request, env, null);
      const rows = await sb(env, 'groups?select=name,subjects&order=name');
      const groups = {};
      rows.forEach(g => { groups[g.name] = { subjects: g.subjects || [] }; });
      return jsonRes({ groups });
    }

    if (path === '/api/admin/groups' && method === 'POST') {
      await requireSession(request, env, ['admin']);
      const body = await readJson(request);
      const groups = validateGroups(body.groups);
      const names = Object.keys(groups);

      const existing = await sb(env, 'groups?select=name');
      for (const g of existing) {
        if (!names.includes(g.name)) {
          await sb(env, `groups?name=eq.${enc(g.name)}`, { method: 'DELETE' });
        }
      }
      if (names.length) {
        await sb(env, 'groups?on_conflict=name', {
          method: 'POST',
          prefer: 'resolution=merge-duplicates',
          body: names.map(name => ({ name, subjects: groups[name].subjects }))
        });
      }
      return jsonRes({ success: true });
    }

    // ===== Horarios =====
    if (path.startsWith('/api/admin/schedules/') && method === 'GET') {
      const s = await requireSession(request, env, ['admin', 'docente', 'alumno']);
      const groupName = decodeURIComponent(path.split('/').pop());
      if (s.role === 'alumno' && groupName !== s.grupo) {
        throw new HttpError(403, 'Solo puedes consultar el horario de tu grupo.');
      }
      const rows = await sb(env, `schedules?select=schedule&group_name=eq.${enc(groupName)}&limit=1`);
      return jsonRes({ schedule: rows[0]?.schedule || [] });
    }

    if (path === '/api/admin/schedules' && method === 'POST') {
      await requireSession(request, env, ['admin']);
      const { group, schedule } = await readJson(request);
      const clean = validateSchedule(group, schedule);
      await sb(env, 'schedules?on_conflict=group_name', {
        method: 'POST',
        prefer: 'resolution=merge-duplicates',
        body: { group_name: group, schedule: clean }
      });
      return jsonRes({ success: true });
    }

    // ===== Notificaciones =====
    if (path === '/api/notifications' && method === 'GET') {
      // Sin verificar al usuario en la base en cada consulta, porque el alumno consulta cada 5 segundos
      const s = await requireSession(request, env, ['alumno', 'docente', 'admin'], { verifyUser: false });
      // El alumno solo ve los avisos de SU grupo (sale de su sesion, no de la peticion)
      const group = s.role === 'alumno' ? s.grupo : url.searchParams.get('group');
      let query = 'notifications?select=*&order=created_at.desc&limit=100';
      if (group) query += `&group_name=eq.${enc(group)}`;
      const rows = await sb(env, query);
      return jsonRes({ notifications: rows.map(formatNotification) });
    }

    if (path === '/api/notifications' && method === 'POST') {
      const s = await requireSession(request, env, ['docente']);
      const b = await readJson(request);
      const message = str(b.message, 500);
      const classroom = str(b.classroom, 40);

      // El profesor sale de la sesion, no de lo que mande la pagina
      const classes = await findCurrentClasses(env, s.name);
      if (!classes.length) {
        throw new HttpError(409, 'No tienes una clase asignada en este horario. Verifica que tu horario esté registrado en el panel de administración.');
      }

      const rows = await sb(env, 'notifications', {
        method: 'POST',
        prefer: 'return=representation',
        body: classes.map(c => ({
          teacher_name: s.name,
          classroom,
          message,
          group_name: c.group,
          subject: c.subject
        }))
      });
      return jsonRes({
        success: true,
        notification: formatNotification(rows[0]),
        groups: classes.map(c => ({ group: c.group, subject: c.subject, time: c.time }))
      });
    }

    if (path === '/api/teacher/current' && method === 'GET') {
      const s = await requireSession(request, env, ['docente']);
      const classes = await findCurrentClasses(env, s.name);
      return jsonRes({
        classes: classes.map(c => ({ group: c.group, subject: c.subject, time: c.time }))
      });
    }

    // ===== Asistencia (solo docentes, solo de su clase en curso) =====
    if (path === '/api/teacher/attendance' && method === 'GET') {
      const s = await requireSession(request, env, ['docente']);
      const group = url.searchParams.get('group') || '';
      const cls = await classForGroup(env, s.name, group);
      const date = todayMexico();

      const students = sortStudents((await groupStudents(env, group)).map(studentRow));
      const rows = await sb(env,
        `attendance?select=student_id,status&class_date=eq.${date}&group_name=eq.${enc(group)}` +
        `&subject=eq.${enc(cls.subject)}&class_time=eq.${enc(cls.time)}`);
      const saved = {};
      rows.forEach(r => { saved[r.student_id] = r.status; });

      return jsonRes({ group, subject: cls.subject, time: cls.time, date, students, saved });
    }

    if (path === '/api/teacher/attendance' && method === 'POST') {
      const s = await requireSession(request, env, ['docente']);
      const b = await readJson(request);
      const group = typeof b.group === 'string' ? b.group : '';
      const cls = await classForGroup(env, s.name, group);

      const records = Array.isArray(b.records) ? b.records : [];
      if (!records.length || records.length > 200) throw new HttpError(400, 'Lista de asistencia no válida.');

      // Solo se aceptan alumnos que realmente pertenecen a ese grupo
      const byId = new Map((await groupStudents(env, group)).map(u => [Number(u.id), studentRow(u)]));
      const date = todayMexico();
      const seen = new Set();

      const body = records.map(r => {
        const id = Number(r?.studentId);
        const st = byId.get(id);
        if (!st || !ATTENDANCE_STATUS.includes(r.status) || seen.has(id)) {
          throw new HttpError(400, 'La lista incluye alumnos o estados no válidos.');
        }
        seen.add(id);
        return {
          class_date: date,
          group_name: group,
          subject: cls.subject,
          class_time: cls.time,
          teacher_name: s.name,
          student_id: id,
          student_name: `${st.appPaterno} ${st.appMaterno} ${st.nombre}`.replace(/\s+/g, ' ').trim(),
          status: r.status,
          updated_at: new Date().toISOString()
        };
      });

      // Si ya habia una lista de esta misma clase y dia, se actualiza en lugar de duplicarse
      await sb(env, 'attendance?on_conflict=class_date,group_name,subject,class_time,student_id', {
        method: 'POST',
        prefer: 'resolution=merge-duplicates',
        body
      });
      return jsonRes({ success: true, saved: body.length, subject: cls.subject, time: cls.time });
    }

    return jsonRes({ success: false, message: 'Ruta no encontrada' }, 404);
  } catch (err) {
    if (err instanceof HttpError) return jsonRes({ success: false, message: err.message }, err.status);
    console.error(err);
    return jsonRes({
      success: false,
      message: 'Error interno en el servidor',
      ...(env.DEBUG === '1' ? { error: err.message } : {})
    }, 500);
  }
}

// Cloudflare Pages Functions
export async function onRequest(context) {
  const res = await handle(context.request, context.env);
  return res || context.next();
}

// Cloudflare Workers
export default {
  async fetch(request, env) {
    const res = await handle(request, env);
    if (res) return res;
    return env.ASSETS ? env.ASSETS.fetch(request) : new Response('Recurso no encontrado', { status: 404 });
  }
};
