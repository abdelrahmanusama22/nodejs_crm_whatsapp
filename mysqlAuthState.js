/**
 * MySQL-backed Baileys auth state.
 *
 * Replaces `useMultiFileAuthState` (thousands of small JSON files, heavy I/O and file-lock conflicts
 * on Windows) with rows in the `wa_auth_states` table shared with the Laravel CRM:
 *
 *   wa_auth_states(id, tenant_id, session_id, key_id, key_data, created_at, updated_at)
 *     session_id : gateway session ("user_9", "default")
 *     key_id     : "creds", "pre-key-12", "session-2010...", "app-state-sync-key-xxx" ...
 *     key_data   : BufferJSON-serialized payload
 *
 * Uses a `mysql2/promise` connection pool, so every query is non-blocking.
 *
 * Connection settings (env, defaults match the CRM's local .env):
 *   DB_HOST=127.0.0.1  DB_PORT=3306  DB_DATABASE=inboxhq_db  DB_USERNAME=root  DB_PASSWORD=root
 *   DB_POOL_SIZE=10
 */
const fs = require('fs');
const path = require('path');
const { proto, initAuthCreds, BufferJSON } = require('@whiskeysockets/baileys');

const TABLE = 'wa_auth_states';
const CREDS_KEY = 'creds';
const BATCH_SIZE = 200;

let pool = null;

// session_id -> true when a `creds` row exists (lets sync code answer "is there a saved session?")
const credSessions = new Set();
// session_id -> live creds object of the running socket
const credsCache = new Map();
// session_id -> promise chain, serializes writes per session (no deadlocks / out-of-order creds)
const writeQueues = new Map();

function getPool() {
    if (pool) return pool;

    let mysql;
    try {
        mysql = require('mysql2/promise');
    } catch (err) {
        throw new Error('The "mysql2" package is not installed. Run `npm install mysql2` inside the whatsapp-service folder.');
    }

    pool = mysql.createPool({
        host: process.env.DB_HOST || '127.0.0.1',
        port: Number(process.env.DB_PORT || 3306),
        user: process.env.DB_USERNAME || 'root',
        password: process.env.DB_PASSWORD ?? 'root',
        database: process.env.DB_DATABASE || 'inboxhq_db',
        waitForConnections: true,
        connectionLimit: Number(process.env.DB_POOL_SIZE || 10),
        queueLimit: 0,
        charset: 'utf8mb4',
        enableKeepAlive: true,
        keepAliveInitialDelay: 10000,
    });

    return pool;
}

function chunk(list, size) {
    const out = [];
    for (let i = 0; i < list.length; i += size) out.push(list.slice(i, i + size));
    return out;
}

function enqueue(sessionId, task) {
    const previous = writeQueues.get(sessionId) || Promise.resolve();
    const next = previous.catch(() => {}).then(task);
    writeQueues.set(sessionId, next);
    next
        .finally(() => {
            if (writeQueues.get(sessionId) === next) writeQueues.delete(sessionId);
        })
        .catch(() => {});
    return next;
}

async function withRetry(fn, attempts = 3) {
    let lastErr;
    for (let i = 0; i < attempts; i++) {
        try {
            return await fn();
        } catch (err) {
            lastErr = err;
            // 1213 = deadlock, 1205 = lock wait timeout
            if (err && (err.errno === 1213 || err.errno === 1205) && i < attempts - 1) {
                await new Promise((r) => setTimeout(r, 50 * (i + 1)));
                continue;
            }
            throw err;
        }
    }
    throw lastErr;
}

/**
 * Verifies the DB connection + table and loads the list of sessions that already have creds.
 * Call once on boot; throws a descriptive error when something is wrong.
 */
async function init() {
    const db = getPool();
    try {
        const [rows] = await db.query(`SELECT DISTINCT session_id FROM ${TABLE} WHERE key_id = ?`, [CREDS_KEY]);
        credSessions.clear();
        for (const row of rows) credSessions.add(row.session_id);
    } catch (err) {
        if (err && err.code === 'ER_NO_SUCH_TABLE') {
            throw new Error(`Table "${TABLE}" does not exist. Run \`php artisan migrate\` in the Laravel project first.`);
        }
        throw err;
    }
    return [...credSessions];
}

/** users.tenant_id for "user_<id>" sessions (null for "default" / unknown). */
async function resolveTenantId(sessionId) {
    const match = /^user_(\d+)$/.exec(sessionId);
    if (!match) return null;
    try {
        const [rows] = await getPool().query('SELECT tenant_id FROM users WHERE id = ? LIMIT 1', [Number(match[1])]);
        return rows[0]?.tenant_id ?? null;
    } catch (_) {
        return null;
    }
}

// ── Low-level row helpers ────────────────────────────────────────────────────

async function readRows(sessionId, keyIds) {
    const result = new Map();
    for (const ids of chunk(keyIds, 500)) {
        const [rows] = await getPool().query(
            `SELECT key_id, key_data FROM ${TABLE} WHERE session_id = ? AND key_id IN (?)`,
            [sessionId, ids],
        );
        for (const row of rows) {
            try {
                result.set(row.key_id, JSON.parse(row.key_data, BufferJSON.reviver));
            } catch (_) {
                // corrupted row: treat as missing
            }
        }
    }
    return result;
}

async function writeRows(sessionId, tenantId, entries) {
    if (entries.length === 0) return;
    const now = new Date();
    // Sorted by key so concurrent writers always lock rows in the same order
    const sorted = [...entries].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    for (const part of chunk(sorted, BATCH_SIZE)) {
        const values = part.map(([keyId, data]) => [
            tenantId,
            sessionId,
            keyId,
            JSON.stringify(data, BufferJSON.replacer),
            now,
            now,
        ]);
        await withRetry(() =>
            getPool().query(
                `INSERT INTO ${TABLE} (tenant_id, session_id, key_id, key_data, created_at, updated_at) VALUES ?
                 ON DUPLICATE KEY UPDATE
                    key_data = VALUES(key_data),
                    tenant_id = COALESCE(VALUES(tenant_id), tenant_id),
                    updated_at = VALUES(updated_at)`,
                [values],
            ),
        );
    }
}

async function deleteRows(sessionId, keyIds) {
    for (const ids of chunk(keyIds, 500)) {
        await withRetry(() =>
            getPool().query(`DELETE FROM ${TABLE} WHERE session_id = ? AND key_id IN (?)`, [sessionId, ids]),
        );
    }
}

/** Reads one key of any session (used for LID -> phone lookups outside of a socket). */
async function readKey(sessionId, keyId) {
    const rows = await readRows(sessionId, [keyId]);
    return rows.get(keyId) ?? null;
}

/** Deletes the whole auth state of a session (logout / invalid credentials). */
async function removeSession(sessionId) {
    credSessions.delete(sessionId);
    credsCache.delete(sessionId);
    await enqueue(sessionId, () =>
        withRetry(() => getPool().query(`DELETE FROM ${TABLE} WHERE session_id = ?`, [sessionId])),
    );
}

/**
 * One-time migration: imports an existing `useMultiFileAuthState` folder into MySQL.
 * Only runs when the DB has no creds for the session yet. The folder is left untouched.
 */
async function importFromFolder(sessionId, folder, tenantId = null) {
    const credsFile = path.join(folder, 'creds.json');
    if (!fs.existsSync(credsFile)) return 0;

    const entries = [];
    for (const name of fs.readdirSync(folder)) {
        if (!name.endsWith('.json')) continue;
        let raw;
        try {
            raw = fs.readFileSync(path.join(folder, name), 'utf8');
            JSON.parse(raw); // skip corrupted files
        } catch (_) {
            continue;
        }
        const base = name.slice(0, -'.json'.length);
        // Reverse Baileys' fixFileName(): "/" -> "__", ":" -> "-"  ("::" separators became "--")
        const keyId = base === 'creds' ? CREDS_KEY : base.replace(/__/g, '/').replace(/--/g, '::');
        entries.push([keyId, JSON.parse(raw, BufferJSON.reviver)]);
    }

    await enqueue(sessionId, () => writeRows(sessionId, tenantId, entries));
    credSessions.add(sessionId);
    console.log(`[${sessionId}] Imported ${entries.length} auth files from disk into MySQL (${TABLE}).`);
    return entries.length;
}

/**
 * Drop-in replacement for `useMultiFileAuthState(folder)`.
 *
 * @param {string} sessionId  e.g. "user_9" or "default"
 * @param {{ legacyFolder?: string }} [options]  folder of a previous file-based session to import once
 * @returns {Promise<{ state: object, saveCreds: () => Promise<void>, readData, writeData, removeData }>}
 */
async function useMySQLAuthState(sessionId, options = {}) {
    const tenantId = await resolveTenantId(sessionId);

    // --- readData / writeData / removeData: map 1:1 to wa_auth_states rows ---
    const readData = async (keyId) => {
        try {
            return await readKey(sessionId, keyId);
        } catch (err) {
            console.warn(`[${sessionId}] readData(${keyId}) failed:`, err.message);
            return null;
        }
    };

    const writeData = (data, keyId) => enqueue(sessionId, () => writeRows(sessionId, tenantId, [[keyId, data]]));

    const removeData = (keyId) => enqueue(sessionId, () => deleteRows(sessionId, [keyId]));

    // One-time import of the old on-disk session so nobody has to re-scan the QR code
    if (options.legacyFolder && !(await readRows(sessionId, [CREDS_KEY])).has(CREDS_KEY)) {
        try {
            await importFromFolder(sessionId, options.legacyFolder, tenantId);
        } catch (err) {
            console.error(`[${sessionId}] Failed importing legacy auth folder:`, err.message);
        }
    }

    const creds = (await readData(CREDS_KEY)) || initAuthCreds();
    credsCache.set(sessionId, creds);

    return {
        state: {
            creds,
            keys: {
                get: async (type, ids) => {
                    const data = {};
                    const rows = await readRows(sessionId, ids.map((id) => `${type}-${id}`));
                    for (const id of ids) {
                        let value = rows.get(`${type}-${id}`) ?? null;
                        if (type === 'app-state-sync-key' && value) {
                            value = proto.Message.AppStateSyncKeyData.fromObject(value);
                        }
                        data[id] = value;
                    }
                    return data;
                },
                set: async (data) => {
                    const upserts = [];
                    const removals = [];
                    for (const category in data) {
                        for (const id in data[category]) {
                            const value = data[category][id];
                            const keyId = `${category}-${id}`;
                            if (value) upserts.push([keyId, value]);
                            else removals.push(keyId);
                        }
                    }
                    if (upserts.length === 0 && removals.length === 0) return;
                    await enqueue(sessionId, async () => {
                        await writeRows(sessionId, tenantId, upserts);
                        if (removals.length) await deleteRows(sessionId, removals);
                    });
                },
            },
        },
        saveCreds: async () => {
            await writeData(creds, CREDS_KEY);
            credSessions.add(sessionId);
        },
        readData,
        writeData,
        removeData,
    };
}

module.exports = {
    useMySQLAuthState,
    init,
    readKey,
    removeSession,
    importFromFolder,
    hasCreds: (sessionId) => credSessions.has(sessionId),
    listCredSessions: () => [...credSessions],
    getCachedCreds: (sessionId) => credsCache.get(sessionId) || null,
    close: async () => {
        if (pool) {
            await pool.end();
            pool = null;
        }
    },
};
