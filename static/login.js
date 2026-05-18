async function doLogin() {
    const pw = document.getElementById('pw').value;
    const err = document.getElementById('error');
    try {
        const res = await fetch('/api/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({password: pw}) });
        const data = await res.json();
        if (data.authenticated) { window.location.href = '/dashboard'; }
        else { err.textContent = data.message || 'Invalid password'; err.style.display = 'block'; }
    } catch (e) { err.textContent = 'Network error'; err.style.display = 'block'; }
}

document.getElementById('login-btn').addEventListener('click', doLogin);
document.getElementById('pw').addEventListener('keydown', e => {
    if (e.key === 'Enter') doLogin();
});
