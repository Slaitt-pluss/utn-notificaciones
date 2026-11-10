document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    const errorMsg = document.getElementById('errorMsg');

    errorMsg.textContent = '';

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (data.success) {
            // Guardamos los datos actualizados, asegurando el grupo correcto
            sessionStorage.setItem('userName', data.user.name);
            sessionStorage.setItem('userRole', data.user.role);
            sessionStorage.setItem('userGroup', data.user.grupo);

            if (data.user.role === 'admin') {
                window.location.href = 'admin.html';
            } else if (data.user.role === 'docente') {
                window.location.href = 'docente.html';
            } else if (data.user.role === 'alumno') {
                window.location.href = 'alumno.html';
            }
        } else {
            errorMsg.textContent = data.message || 'Usuario o contraseña incorrectos';
        }
    } catch (error) {
        console.error('Error en el login:', error);
        errorMsg.textContent = 'Error de conexión con el servidor';
    }
});