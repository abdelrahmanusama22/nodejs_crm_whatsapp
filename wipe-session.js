/**
 * Dedicated WhatsApp Session Cleanup Script (`wipe-session.js`)
 *
 * Purges all persisted E2EE keys and credentials for a session from the `wa_auth_states`
 * MySQL table and removes any leftover `sessions/<session_id>` directory on disk.
 *
 * Usage:
 *   node wipe-session.js user_11
 */
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

// Load .env if present (lightweight parser, zero extra dependencies)
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
    try {
        const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;
            const eqIdx = trimmed.indexOf('=');
            if (eqIdx === -1) continue;
            const k = trimmed.slice(0, eqIdx).trim();
            const v = trimmed.slice(eqIdx + 1).trim().replace(/^['"]|['"]$/g, '');
            if (k && process.env[k] === undefined) {
                process.env[k] = v;
            }
        }
    } catch (_) {}
}

function resolveSessionId(arg) {
    const raw = String(arg || 'user_11').trim();
    if (raw === 'default') return 'default';
    return raw.startsWith('user_') ? raw : `user_${raw}`;
}

async function wipeSession() {
    const sessionId = resolveSessionId(process.argv[2]);
    const numericId = sessionId.replace(/^user_/, '');

    const dbConfig = {
        host: process.env.DB_HOST || '127.0.0.1',
        port: Number(process.env.DB_PORT || 3306),
        user: process.env.DB_USERNAME || 'root',
        password: process.env.DB_PASSWORD ?? 'root',
        database: process.env.DB_DATABASE || 'inboxhq_db',
        charset: 'utf8mb4',
    };

    console.log(`[WipeSession] Target session: "${sessionId}"`);
    console.log(`[WipeSession] Connecting to MySQL (${dbConfig.host}:${dbConfig.port}/${dbConfig.database})...`);

    const connection = await mysql.createConnection(dbConfig);

    try {
        // 1. Scan wa_auth_states for the exact session ID
        const [countRows] = await connection.execute(
            'SELECT COUNT(*) AS total FROM wa_auth_states WHERE session_id = ? OR session_id = ?',
            [sessionId, numericId]
        );
        const foundCount = Number(countRows[0]?.total || 0);
        console.log(`[WipeSession] Found ${foundCount} corrupted key(s) in wa_auth_states for session "${sessionId}".`);

        // 2. Forcefully delete all matching rows from wa_auth_states
        if (foundCount > 0) {
            const [deleteResult] = await connection.execute(
                'DELETE FROM wa_auth_states WHERE session_id = ? OR session_id = ?',
                [sessionId, numericId]
            );
            console.log(`[WipeSession] Deleted ${deleteResult.affectedRows} row(s) from wa_auth_states.`);
        } else {
            console.log(`[WipeSession] No rows to delete in wa_auth_states for "${sessionId}".`);
        }

        // 3. Check if sessions/<session_id> directory exists on disk and remove it
        const sessionDir = path.join(__dirname, 'sessions', sessionId);
        if (fs.existsSync(sessionDir)) {
            fs.rmSync(sessionDir, { recursive: true, force: true });
            console.log(`[WipeSession] Removed local directory on disk: ${sessionDir}`);
        } else {
            console.log(`[WipeSession] Local directory already absent: ${sessionDir}`);
        }
    } finally {
        // 4. Close DB connection
        await connection.end();
        console.log('[WipeSession] MySQL connection closed.');
    }

    // 5. Print clear completion message
    console.log(`\n✅ Clean Slate Ready for "${sessionId}"! Restart the Node.js gateway to generate a fresh QR code.`);
}

wipeSession().catch((err) => {
    console.error('[WipeSession] ERROR:', err.message || err);
    process.exit(1);
});
