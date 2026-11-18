// Backend para Cloudflare conectado a Supabase (usa la API REST de Supabase con fetch,
// asi no depende de ningun paquete npm).
// Variables de entorno necesarias en Cloudflare: SUPABASE_URL y SUPABASE_SERVICE_KEY

const enc = encodeURIComponent;

async function sb(env, pathAndQuery, { method = 'GET', body, prefer } = {}) {
  const key = env.SUPABASE_SERVICE_KEY;
  if (!key || !env.SUPABASE_URL) {
    throw new Error(
      'Faltan variables. El Worker solo recibe estas: ' + Object.keys(env).join(', ')
    );
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

// Fila de la tabla users -> formato que ya usaba tu frontend
function formatUser(u) {
  return {
    ...(u.extra || {}),
    id: u.id,
    username: u.username,
    password: u.password,
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
    timestamp: new Date(n.created_at).toLocaleTimeString('es-MX', {
      timeZone: 'America/Mexico_City'
    })
  };
}

// ---------- Deteccion automatica de la clase del profesor segun el horario ----------
const TZ = 'America/Mexico_City';
const EARLY_MIN = 15; // minutos antes de que empiece la clase en los que ya puede avisar

// Minusculas y sin acentos, para comparar "Miércoles" con "miercoles"
const norm = s => String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').trim().toLowerCase();

// Dia de la semana y minutos transcurridos del dia, en hora de Mexico
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

// Busca en los horarios de todos los grupos la(s) clase(s) que el profesor tiene ahora
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

// Devuelve una Response para rutas /api/*, o null si la ruta no es de la API
async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '');
  const method = request.method;

  if (!path.startsWith('/api/')) return null;

  const jsonRes = (data, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json;charset=UTF-8' }
    });

  try {
    // 1. Login
    if (path === '/api/login' && method === 'POST') {
      const { username, password } = await request.json();
      const rows = await sb(
        env,
        `users?select=*&username=eq.${enc(username || '')}&password=eq.${enc(password || '')}&limit=1`
      );
      const user = rows[0];

      if (user) {
        return jsonRes({
          success: true,
          user: {
            name: user.name || `${user.nombre || ''} ${user.app_paterno || ''}`.trim(),
            role: user.role,
            grupo: user.grupo || 'N/A'
          }
        });
      }
      return jsonRes({ success: false, message: 'Usuario o contraseña incorrectos' }, 401);
    }

    // 2. Lista de usuarios (Admin)
    if (path === '/api/admin/users' && method === 'GET') {
      const rows = await sb(env, 'users?select=*&order=id');
      return jsonRes({ users: rows.map(formatUser) });
    }

    // 3. Agregar usuario (Admin)
    if (path === '/api/admin/users' && method === 'POST') {
      const { username, password, name, nombre, appPaterno, role, grupo, id, ...extra } =
        await request.json();

      const rows = await sb(env, 'users', {
        method: 'POST',
        prefer: 'return=representation',
        body: { username, password, name, nombre, app_paterno: appPaterno, role, grupo, extra }
      });
      return jsonRes({ success: true, user: formatUser(rows[0]) });
    }

    // 4. Eliminar usuario (Admin)
    if (path.startsWith('/api/admin/users/') && method === 'DELETE') {
      const userId = Number(path.split('/').pop());
      await sb(env, `users?id=eq.${userId}`, { method: 'DELETE' });
      return jsonRes({ success: true });
    }

    // 5. Obtener grupos (con sus materias)
    if (path === '/api/admin/groups' && method === 'GET') {
      const rows = await sb(env, 'groups?select=name,subjects&order=name');
      const groups = {};
      rows.forEach(g => { groups[g.name] = { subjects: g.subjects || [] }; });
      return jsonRes({ groups });
    }

    // 6. Guardar grupos y materias (reemplaza la lista completa)
    if (path === '/api/admin/groups' && method === 'POST') {
      const body = await request.json();
      let groups = body.groups || {};

      // Compatibilidad: si llega una lista simple, la convierte al formato nuevo
      if (Array.isArray(groups)) {
        const obj = {};
        groups.forEach(n => { obj[n] = { subjects: [] }; });
        groups = obj;
      }

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
          body: names.map(name => ({ name, subjects: groups[name].subjects || [] }))
        });
      }
      return jsonRes({ success: true });
    }

    // 7. Horario de un grupo
    if (path.startsWith('/api/admin/schedules/') && method === 'GET') {
      const groupName = decodeURIComponent(path.split('/').pop());
      const rows = await sb(env, `schedules?select=schedule&group_name=eq.${enc(groupName)}&limit=1`);
      return jsonRes({ schedule: rows[0]?.schedule || [] });
    }

    // 8. Guardar horario de un grupo
    if (path === '/api/admin/schedules' && method === 'POST') {
      const { group, schedule } = await request.json();
      await sb(env, 'schedules?on_conflict=group_name', {
        method: 'POST',
        prefer: 'resolution=merge-duplicates',
        body: { group_name: group, schedule: schedule || [] }
      });
      return jsonRes({ success: true });
    }

    // 9. Obtener notificaciones (si viene ?group=4IV1, solo las de ese grupo)
    if (path === '/api/notifications' && method === 'GET') {
      const group = url.searchParams.get('group');
      let query = 'notifications?select=*&order=created_at.desc&limit=100';
      if (group) query += `&group_name=eq.${enc(group)}`;
      const rows = await sb(env, query);
      return jsonRes({ notifications: rows.map(formatNotification) });
    }

    // 10. Enviar notificacion (Docentes): el grupo se detecta solo con el horario
    if (path === '/api/notifications' && method === 'POST') {
      const { teacherName, classroom, message } = await request.json();

      const classes = await findCurrentClasses(env, teacherName);
      if (!classes.length) {
        return jsonRes({
          success: false,
          message: 'No tienes una clase asignada en este horario. Verifica que tu horario esté registrado en el panel de administración.'
        }, 409);
      }

      const rows = await sb(env, 'notifications', {
        method: 'POST',
        prefer: 'return=representation',
        body: classes.map(c => ({
          teacher_name: teacherName,
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

    // 11. Clase actual del profesor (para mostrarla en su panel)
    if (path === '/api/teacher/current' && method === 'GET') {
      const name = url.searchParams.get('name') || '';
      const classes = await findCurrentClasses(env, name);
      return jsonRes({
        classes: classes.map(c => ({ group: c.group, subject: c.subject, time: c.time }))
      });
    }

    return jsonRes({ success: false, message: 'Ruta no encontrada' }, 404);
  } catch (err) {
    console.error(err);
    return jsonRes({ success: false, message: 'Error interno en el servidor', error: err.message }, 500);
  }
}

// Cloudflare Pages Functions
export async function onRequest(context) {
  const res = await handle(context.request, context.env);
  return res || context.next();
}

// Cloudflare Workers (por si lo desplegaste como Worker)
export default {
  async fetch(request, env) {
    const res = await handle(request, env);
    if (res) return res;
    return env.ASSETS ? env.ASSETS.fetch(request) : new Response('Recurso no encontrado', { status: 404 });
  }
};
