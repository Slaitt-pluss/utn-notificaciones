export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Helper para respuestas JSON estandarizadas
    const jsonRes = (data, status = 200) => new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json;charset=UTF-8' }
    });

    // Funciones auxiliares para interactuar con Cloudflare KV
    async function getKV(key, defaultValue) {
      try {
        const val = await env.UTN_KV.get(key, 'json');
        return val !== null ? val : defaultValue;
      } catch (e) {
        return defaultValue;
      }
    }

    async function setKV(key, value) {
      await env.UTN_KV.put(key, JSON.stringify(value));
    }

    try {
      // 1. Ruta para procesar el Login
      if (path === '/api/login' && method === 'POST') {
        const { username, password } = await request.json();
        const db = await getKV('users_db', { users: [] });
        const user = db.users.find(u => u.username === username && u.password === password);

        if (user) {
          return jsonRes({ 
            success: true, 
            user: { 
              name: user.name || `${user.nombre || ''} ${user.appPaterno || ''}`.trim(), 
              role: user.role, 
              grupo: user.grupo || 'N/A' 
            } 
          });
        } else {
          return jsonRes({ success: false, message: 'Usuario o contraseña incorrectos' }, 401);
        }
      }

      // 2. Obtener lista completa de usuarios (Admin)
      if (path === '/api/admin/users' && method === 'GET') {
        const db = await getKV('users_db', { users: [] });
        return jsonRes(db);
      }

      // 3. Registrar o Agregar Usuario (Admin)
      if (path === '/api/admin/users' && method === 'POST') {
        const newUser = await request.json();
        const db = await getKV('users_db', { users: [] });

        newUser.id = Date.now();
        db.users.push(newUser);
        await setKV('users_db', db);

        return jsonRes({ success: true, user: newUser });
      }

      // 4. Eliminar Usuario por ID (Admin)
      if (path.startsWith('/api/admin/users/') && method === 'DELETE') {
        const userId = Number(path.split('/').pop());
        const db = await getKV('users_db', { users: [] });
        
        db.users = db.users.filter(u => u.id !== userId);
        await setKV('users_db', db);

        return jsonRes({ success: true });
      }

      // 5. Obtener Grupos Académicos
      if (path === '/api/admin/groups' && method === 'GET') {
        const db = await getKV('groups_db', { groups: ['4IV1', '4IV2', '5IV1'] });
        return jsonRes(db);
      }

      // 6. Guardar / Actualizar Grupos Académicos
      if (path === '/api/admin/groups' && method === 'POST') {
        const { groups } = await request.json();
        await setKV('groups_db', { groups });
        return jsonRes({ success: true });
      }

      // 7. Obtener el horario de un grupo específico
      if (path.startsWith('/api/admin/schedules/') && method === 'GET') {
        const groupName = path.split('/').pop();
        const db = await getKV('schedules_db', {});
        return jsonRes({ schedule: db[groupName] || [] });
      }

      // 8. Guardar o actualizar el horario de un grupo
      if (path === '/api/admin/schedules' && method === 'POST') {
        const { group, schedule } = await request.json();
        const db = await getKV('schedules_db', {});
        
        db[group] = schedule;
        await setKV('schedules_db', db);

        return jsonRes({ success: true });
      }

      // 9. Obtener notificaciones
      if (path === '/api/notifications' && method === 'GET') {
        const db = await getKV('notifications_db', { notifications: [] });
        return jsonRes(db);
      }

      // 10. Enviar notificaciones (Docentes)
      if (path === '/api/notifications' && method === 'POST') {
        const { teacherName, classroom, message } = await request.json();
        const db = await getKV('notifications_db', { notifications: [] });

        const newNotification = {
          id: Date.now(),
          teacherName,
          classroom,
          message,
          timestamp: new Date().toLocaleTimeString()
        };

        db.notifications.unshift(newNotification);
        await setKV('notifications_db', db);

        return jsonRes({ success: true, notification: newNotification });
      }

      // Si la ruta no coincide con ninguna API, Cloudflare Pages servirá los archivos estáticos de la carpeta public
      return new Response('Recurso no encontrado', { status: 404 });

    } catch (err) {
      return jsonRes({ success: false, message: 'Error interno en el servidor', error: err.message }, 500);
    }
  }
};