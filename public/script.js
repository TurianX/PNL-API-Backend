console.log("script.js loaded ✅");

// ====== Config (Carrd support) ======
// On Carrd, add this before loading script.js:
//   <script>window.BACKEND = 'https://your-backend.onrender.com';</script>
const BACKEND = window.BACKEND || ''; // '' = same-origin for /staff.html

function api(path, opts = {}) {
    const url = path.startsWith('http') ? path : `${BACKEND}${path}`;
    return fetch(url, { credentials: 'include', ...opts });
}

function goToLiff(nextPath) {
    const next = encodeURIComponent(nextPath || location.pathname + location.search);
    // If you're on Carrd, you can pass your absolute Carrd page in `next` too.
    location.href = `/liff.html?next=${next}`;
}

(async () => {
    // 1) Ensure LINE session exists
    const meRes = await api("/me");
    if (meRes.status === 401) {
        goToLiff(location.pathname + location.search);
        return;
    }
    const { ok, user } = await meRes.json();
    if (!ok) {
        goToLiff(location.pathname + location.search);
        return;
    }

    // 2) Header UI
    const displayName = user.name || user.profileApi?.displayName || "Friend";
    const pic = user.picture || user.profileApi?.pictureUrl || "";
    const helloEl = document.getElementById("hello");
    const avatarEl = document.getElementById("avatar");
    if (helloEl) helloEl.textContent = `Welcome, ${displayName}`;
    if (avatarEl && pic) avatarEl.src = pic;

    // 3) Userbase auth (deterministic bootstrap → sign in → fallbacks → migrate → sign up)
    try {
        const bootRes = await api('/userbase/bootstrap');
        const boot = await bootRes.json();
        if (!boot.ok) throw new Error('Bootstrap failed');

        const { username, password: currentPw } = boot;

        const lineId = user.lineUserId;
        const legacyPw = `pw-${lineId}-2025`;                         // your old scheme (optional fallback)
        const localPw = localStorage.getItem(`ubpw:${lineId}`) || null; // dev-only fallback
        const fallbacks = [legacyPw, localPw].filter(Boolean);

        async function trySignIn(pw) {
            return userbase.signIn({ username, password: pw, rememberMe: 'local' });
        }
        async function migratePasswordIfNeeded(signedInWith) {
            if (signedInWith === currentPw) return;
            try {
                await userbase.updateUser({
                    currentPassword: signedInWith,
                    newPassword: currentPw,
                });
                console.log('[UB] migrated password → canonical');
            } catch (e) {
                console.warn('[UB] migration failed:', e.name, e.message);
            }
        }

        let signedIn = false;

        // Try canonical first
        try {
            await trySignIn(currentPw);
            console.log('[UB] signIn OK (canonical):', username);
            signedIn = true;
        } catch (e1) {
            if (e1.name === 'UserAlreadySignedIn') {
                console.log('[UB] already signed in');
                signedIn = true;
            } else if (e1.name === 'UsernameOrPasswordMismatch' || e1.name === 'WrongPassword') {
                console.warn('[UB] canonical mismatch → trying fallbacks…');
                for (const fb of fallbacks) {
                    try {
                        await trySignIn(fb);
                        console.log('[UB] signIn OK via fallback:', username);
                        await migratePasswordIfNeeded(fb);
                        signedIn = true;
                        break;
                    } catch (eFb) {
                        if (eFb.name === 'UserAlreadySignedIn') {
                            console.log('[UB] already signed in (fallback)');
                            await migratePasswordIfNeeded(fb);
                            signedIn = true;
                            break;
                        }
                    }
                }

                if (!signedIn) {
                    try {
                        const u = await userbase.signUp({
                            username,
                            password: currentPw,
                            rememberMe: 'local',
                            profile: { displayName, pictureUrl: pic },
                        });
                        console.log('[UB] signUp OK (new user):', u.username);
                        signedIn = true;
                    } catch (eSignUp) {
                        console.error('[UB] signUp failed:', eSignUp.name, eSignUp.message);
                    }
                }
            } else if (e1.name === 'UserNotFound' || e1.name === 'UsernameNotFound') {
                try {
                    const u = await userbase.signUp({
                        username,
                        password: currentPw,
                        rememberMe: 'local',
                        profile: { displayName, pictureUrl: pic },
                    });
                    console.log('[UB] signUp OK (first time):', u.username);
                    signedIn = true;
                } catch (e2) {
                    console.error('[UB] signUp failed (first time):', e2.name, e2.message);
                }
            } else {
                console.error('[UB] auth unexpected:', e1.name, e1.message);
            }
        }

        if (!signedIn) {
            alert('Login could not complete. Please try again.');
            return;
        }
        console.log('[UB] ✅ fully authenticated:', username);
    } catch (err) {
        console.error('[UB] bootstrap/auth error:', err);
        // non-blocking
    }

    // 4) Staff form (single handler — remove duplicates)

    const formEl = document.getElementById('staffForm');
    const inputEl = document.getElementById('staffId');
    const resultEl = document.getElementById('result'); // we'll keep for errors only

    if (formEl && inputEl) {
        formEl.addEventListener('submit', async (e) => {
            e.preventDefault();

            const staffId = (inputEl.value || '').trim();
            if (!staffId) return;

            // button UX
            const btn = formEl.querySelector('button[type="submit"]');
            const old = btn.textContent;
            btn.disabled = true;
            btn.textContent = 'Verifying…';

            // hide any previous message
            if (resultEl) { resultEl.style.display = 'none'; resultEl.className = 'result'; resultEl.textContent = ''; }

            try {
                const resp = await fetch('/staff/role', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ staffId }),
                });
                const data = await resp.json();

                if (!resp.ok || !data.ok) {
                    // show only error; keep success silent
                    if (resultEl) {
                        resultEl.style.display = 'block';
                        resultEl.className = 'result error';
                        resultEl.textContent = data?.error || 'Unable to verify Staff ID.';
                    }
                    console.warn('[STAFF] verify failed:', data);
                    btn.disabled = false;
                    btn.textContent = old;
                    return;
                }

                // ✅ Success: log for devs, then close LIFF or show success page
                console.log('[STAFF] verified OK', { staffId, role: data.role, name: data.name, pageId: data.pageId });

                // Build success URL with details for the page to display
                const successUrl = `/success.html?` +
                    `name=${encodeURIComponent(data.name || '')}` +
                    `&staffId=${encodeURIComponent(staffId)}` +
                    `&role=${encodeURIComponent(data.role || '')}`;

                // Fire event (for any listener on liff.html) and try to close LIFF directly
                document.dispatchEvent(new Event('staffLoginSuccess'));

                let closed = false;
                try {
                    if (window.liff && typeof liff.closeWindow === 'function') {
                        liff.closeWindow();
                        closed = true;
                    }
                } catch (e) {
                    console.warn('[STAFF] liff.closeWindow() failed', e);
                }

                // Fallback: if still open after 2s, go to success page (with details)
                setTimeout(() => {
                    if (!closed) window.location.href = successUrl;
                }, 2000);

            } catch (err) {
                console.error('[STAFF] submit error', err);
                if (resultEl) {
                    resultEl.style.display = 'block';
                    resultEl.className = 'result error';
                    resultEl.textContent = 'Network error. Please try again.';
                }
                btn.disabled = false;
                btn.textContent = old;
            }
        });
    }

    // 5) Logout link
    const logoutEl = document.getElementById("logout");
    if (logoutEl) {
        logoutEl.addEventListener("click", (e) => {
            e.preventDefault();
            location.href = "/logout";
        });
    }
})();