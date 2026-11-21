const express = require('express');
const {
    default: makeWASocket,
    DisconnectReason,
    downloadMediaMessage,
    normalizeMessageContent,
    proto,
} = require('@whiskeysockets/baileys');
const authStore = require('./mysqlAuthState');
const qrcode = require('qrcode-terminal');
const QRCodeCore = require('qrcode-terminal/vendor/QRCode');
const QRErrorCorrectLevel = require('qrcode-terminal/vendor/QRCode/QRErrorCorrectLevel');
const axios = require('axios');
const Redis = require('ioredis');
const fs = require('fs');
const path = require('path');
const { Readable, PassThrough } = require('stream');
const ffmpeg = require('fluent-ffmpeg');
const ffmpegPath = require('@ffmpeg-installer/ffmpeg').path;

ffmpeg.setFfmpegPath(ffmpegPath);

process.on('uncaughtException', (err) => {
    console.error('[UncaughtException]', err?.message || err);
});
process.on('unhandledRejection', (reason) => {
    console.error('[UnhandledRejection]', reason?.message || reason);
});

const app = express();
app.use(express.json({ limit: '50mb' }));

const PORT = 3000;
const sessionsRootDir = path.join(__dirname, 'sessions');
const legacyAuthFolder = path.join(__dirname, 'auth_info_baileys');

// Baileys auth state lives in MySQL (table `wa_auth_states`); the old on-disk folders are only
// read once to import existing sessions (see mysqlAuthState.js) and are never written to anymore.
function sessionIdFromAuthFolder(folder) {
    if (!folder) return null;
    if (folder === legacyAuthFolder) return 'default';
    const base = path.basename(folder);
    return base.startsWith('user_') ? base : null;
}

// True when a saved session exists in MySQL or still on disk (not imported yet)
function hasSavedSession(sessionId, folder) {
    return authStore.hasCreds(sessionId) || fs.existsSync(path.join(folder, 'creds.json'));
}

if (!fs.existsSync(sessionsRootDir)) {
    fs.mkdirSync(sessionsRootDir, { recursive: true });
}

// ── Security & Gateway Configuration ──
const API_SECRET = process.env.WHATSAPP_API_SECRET || 'inboxhq-secret-token-2026';

// ── Authentication Middleware ──
function authenticate(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

    if (!API_SECRET || token !== API_SECRET) {
        return res.status(401).json({
            success: false,
            error: 'Unauthorized: Invalid or missing Bearer token.',
        });
    }
    next();
}

/**
 * Pure-JS SVG QR code generator using qrcode-terminal's bundled QRCode matrix.
 * Returns a `data:image/svg+xml;base64,...` data URI with zero external dependencies.
 */
function generateQrSvgDataUri(text) {
    try {
        const qr = new QRCodeCore(-1, QRErrorCorrectLevel.M);
        qr.addData(text);
        qr.make();

        const count = qr.getModuleCount();
        const margin = 2;
        const size = count + margin * 2;
        let paths = '';

        for (let r = 0; r < count; r++) {
            for (let c = 0; c < count; c++) {
                if (qr.isDark(r, c)) {
                    paths += `M${c + margin},${r + margin}h1v1h-1z`;
                }
            }
        }

        const svg =
            `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges">` +
            `<rect width="100%" height="100%" fill="#ffffff"/>` +
            `<path d="${paths}" fill="#09090b"/>` +
            `</svg>`;

        return `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`;
    } catch (err) {
        console.error('Failed to generate QR SVG:', err.message);
        return null;
    }
}

/**
 * Format uptime seconds into human-readable string (e.g. "2d 4h 12m 30s").
 */
function formatUptime(seconds) {
    const sec = Math.floor(Number(seconds) || 0);
    const d = Math.floor(sec / 86400);
    const h = Math.floor((sec % 86400) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    const parts = [];
    if (d > 0) parts.push(`${d}d`);
    if (h > 0 || d > 0) parts.push(`${h}h`);
    if (m > 0 || h > 0 || d > 0) parts.push(`${m}m`);
    parts.push(`${s}s`);
    return parts.join(' ');
}

/**
 * Format memory usage metrics in MB.
 */
function getMemoryMetrics() {
    const mem = process.memoryUsage();
    return {
        rss_mb: Math.round((mem.rss / 1024 / 1024) * 100) / 100,
        heap_used_mb: Math.round((mem.heapUsed / 1024 / 1024) * 100) / 100,
        heap_total_mb: Math.round((mem.heapTotal / 1024 / 1024) * 100) / 100,
        external_mb: Math.round((mem.external / 1024 / 1024) * 100) / 100,
    };
}

/**
 * Extract the connected WhatsApp phone number from a socket's user.id or persisted authState.creds.me.id
 * (e.g. "201012345678:12@s.whatsapp.net" -> "+201012345678").
 */
function getConnectedIdentity(targetSock, fallbackCreds = null) {
    const rawId =
        targetSock?.user?.id ||
        targetSock?.authState?.creds?.me?.id ||
        targetSock?.authState?.state?.creds?.me?.id ||
        fallbackCreds?.me?.id ||
        '';
    if (!rawId) return null;
    const digits = String(rawId).split('@')[0].split(':')[0].replace(/\D/g, '');
    return digits ? `+${digits}` : rawId;
}

function getAccountInfo(targetSock, fallbackCreds = null) {
    const me =
        targetSock?.user ||
        targetSock?.authState?.creds?.me ||
        targetSock?.authState?.state?.creds?.me ||
        fallbackCreds?.me ||
        null;
    return {
        phone: getConnectedIdentity(targetSock, fallbackCreds),
        name: me?.name || me?.notify || null,
        jid: me?.id || null,
    };
}

/**
 * Determine whether a Baileys socket's underlying WebSocket is actively OPEN (readyState === 1).
 */
function isSocketOpen(targetSock) {
    if (!targetSock || !targetSock.ws) return false;
    if (targetSock.ws.readyState === 1) return true;
    if (targetSock.ws.isOpen === true) return true;
    if (targetSock.ws.socket && targetSock.ws.socket.readyState === 1) return true;
    return false;
}

// ── Webhook configuration ──
// Primary transport: Redis list (RPUSH here -> `php artisan wa:redis-listen` BLPOPs it in Laravel).
// The old HTTP webhook is kept ONLY as a fallback so no event is lost while Redis is unreachable.
const WA_REDIS_URL = process.env.WA_REDIS_URL || 'redis://127.0.0.1:1980';
const WA_REDIS_QUEUE = 'wa_webhook_queue';

const redis = new Redis(WA_REDIS_URL, {
    enableOfflineQueue: false,      // fail fast while disconnected instead of buffering in memory
    maxRetriesPerRequest: 1,
    connectTimeout: 5000,
    retryStrategy: (times) => Math.min(times * 250, 3000), // keep reconnecting forever, max every 3s
});

let lastRedisErrorLog = 0;
redis.on('error', (err) => {
    // ioredis emits 'error' on every failed reconnect: log at most every 10s, never throw
    const now = Date.now();
    if (now - lastRedisErrorLog > 10000) {
        lastRedisErrorLog = now;
        console.error(`[Redis] connection error: ${err?.message || err}`);
    }
});
redis.on('ready', () => console.log(`[Redis] connected to ${WA_REDIS_URL}`));
redis.on('end', () => console.warn('[Redis] connection closed'));

const LARAVEL_WEBHOOK_URL = 'http://127.0.0.1/webhooks/baileys';
const LARAVEL_WEBHOOK_HEADERS = {
    'Host': 'crm.test',
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'X-Webhook-Secret': process.env.BAILEYS_WEBHOOK_SECRET || 'inboxhq-secret-token-2026',
};

function forwardToLaravel(payload, label = payload.event || 'event', timeout = 4000, userId = null) {
    const enrichedPayload = { ...payload };
    if (userId !== null && userId !== undefined && userId !== 'default') {
        const numericId = Number(userId);
        enrichedPayload.user_id = !Number.isNaN(numericId) && String(numericId) === String(userId) ? numericId : userId;
        enrichedPayload.session_id = `user_${userId}`;
    }

    return new Promise((resolve) => {
        setImmediate(async () => {
            const who = `user_${userId ?? 'default'}`;

            try {
                await redis.rpush(WA_REDIS_QUEUE, JSON.stringify(enrichedPayload));
                console.log(`[${who}] Queued ${label} to Redis (${WA_REDIS_QUEUE})`);
                resolve({ queued: true });
                return;
            } catch (redisError) {
                console.error(`[${who}] Redis push failed for ${label}: ${redisError.message} - falling back to HTTP webhook`);
            }

            // Fallback: direct HTTP webhook so the event is not dropped
            try {
                const response = await axios.post(LARAVEL_WEBHOOK_URL, enrichedPayload, {
                    headers: LARAVEL_WEBHOOK_HEADERS,
                    timeout,
                });
                console.log(`[${who}] Forwarded ${label} to Laravel webhook (fallback, Status: ${response.status})`);
                resolve(response.data);
            } catch (error) {
                console.error(`[${who}] Failed to forward ${label} to Laravel webhook:`, error.message);
                resolve(null);
            }
        });

    });
}

// ── Media ──
const MAX_MEDIA_BYTES = 25 * 1024 * 1024; // don't base64 anything bigger than this
const MEDIA_TYPES = ['image', 'video', 'audio', 'document', 'sticker', 'contact'];

const silentLogger = {
    level: 'silent',
    trace() {}, debug() {}, info() {}, warn() {}, error() {}, fatal() {},
    child() { return silentLogger; },
};

/**
 * Parse a single vCard 3.0 string into { name, phone, phones, vcard }.
 */
function parseVcardString(rawVcard, fallbackName = null) {
    const vcard = String(rawVcard || '').trim();
    let name = String(fallbackName || '').trim();

    if (!name && vcard) {
        const fnMatch = vcard.match(/^FN(?:;[^:]*)?:(.+)$/im);
        if (fnMatch && fnMatch[1]) {
            name = fnMatch[1].trim();
        } else {
            const nMatch = vcard.match(/^N(?:;[^:]*)?:([^;\r\n]*);([^;\r\n]*)/im);
            if (nMatch) {
                name = `${(nMatch[2] || '').trim()} ${(nMatch[1] || '').trim()}`.trim();
            }
        }
    }

    const phones = [];
    if (vcard) {
        const lines = vcard.split(/\r?\n/);
        for (const line of lines) {
            if (!/^(?:item\d+\.)?TEL/i.test(line)) continue;
            const waidMatch = line.match(/waid=(\d+)/i);
            const valuePart = line.includes(':') ? line.split(':').slice(1).join(':').trim() : '';
            const rawDigits = waidMatch?.[1] || valuePart.replace(/\D/g, '');
            if (rawDigits) {
                const formatted = `+${rawDigits}`;
                if (!phones.includes(formatted)) {
                    phones.push(formatted);
                }
            } else if (valuePart && !phones.includes(valuePart)) {
                phones.push(valuePart);
            }
        }
    }

    return {
        name: name || phones[0] || 'Contact',
        phone: phones[0] || '',
        phones,
        vcard,
    };
}

/**
 * Extract contact card(s) if the unwrapped message is contactMessage or contactsArrayMessage.
 */
function extractIncomingContacts(content) {
    if (content?.contactMessage) {
        const node = content.contactMessage;
        const parsed = parseVcardString(node.vcard, node.displayName);
        return {
            contacts: [parsed],
            displayName: parsed.name,
            contextInfo: node.contextInfo || null,
        };
    }

    if (content?.contactsArrayMessage) {
        const node = content.contactsArrayMessage;
        const rawList = Array.isArray(node.contacts) ? node.contacts : [];
        const contacts = rawList
            .map(c => parseVcardString(c?.vcard, c?.displayName))
            .filter(c => c.name || c.phone || c.vcard);

        if (contacts.length === 0) return null;
        return {
            contacts,
            displayName: node.displayName || contacts[0]?.name || 'Contacts',
            contextInfo: node.contextInfo || null,
        };
    }

    return null;
}

/**
 * Build a WhatsApp-compatible vCard 3.0 string from { name, phone, vcard? }.
 */
function buildVcardString(contactObj = {}) {
    if (contactObj?.vcard && /BEGIN:VCARD/i.test(String(contactObj.vcard))) {
        return String(contactObj.vcard).trim();
    }

    const cleanName = String(contactObj?.name || contactObj?.displayName || 'Contact').replace(/[\r\n]+/g, ' ').trim() || 'Contact';
    let digits = String(contactObj?.phone || '').replace(/\D/g, '');
    if (digits.length === 11 && digits.startsWith('01')) {
        digits = `2${digits}`;
    } else if (digits.startsWith('00') && digits.length > 4) {
        digits = digits.slice(2);
    }
    const displayPhone = digits ? `+${digits}` : String(contactObj?.phone || '').trim();

    const lines = [
        'BEGIN:VCARD',
        'VERSION:3.0',
        `FN:${cleanName}`,
        `N:;${cleanName};;;`,
    ];
    if (digits) {
        lines.push(`TEL;type=CELL;type=VOICE;waid=${digits}:${displayPhone}`);
    } else if (displayPhone) {
        lines.push(`TEL;type=CELL:${displayPhone}`);
    }
    lines.push('END:VCARD');
    return lines.join('\n');
}

/** Return { mediaType, node } if the (already unwrapped) message content is image/video/audio/document/sticker. */
function detectIncomingMedia(content) {
    if (content?.imageMessage) return { mediaType: 'image', node: content.imageMessage };
    if (content?.videoMessage) return { mediaType: 'video', node: content.videoMessage };
    if (content?.audioMessage) return { mediaType: 'audio', node: content.audioMessage };
    if (content?.documentMessage) return { mediaType: 'document', node: content.documentMessage };
    if (content?.stickerMessage) return { mediaType: 'sticker', node: content.stickerMessage };
    return null;
}

/**
 * Download + base64-encode an incoming media message.
 * Never throws: failures are reported as { error } so the text/caption still reaches Laravel.
 */
async function downloadIncomingMedia(targetSock, msg, { mediaType, node }) {
    const declaredSize = Number(node.fileLength?.toString?.() ?? node.fileLength ?? 0);
    if (declaredSize > MAX_MEDIA_BYTES) {
        console.warn(`Skipping ${mediaType}: ${declaredSize} bytes exceeds ${MAX_MEDIA_BYTES}`);
        return { error: 'too_large' };
    }

    try {
        const buffer = await downloadMediaMessage(
            msg,
            'buffer',
            {},
            { logger: silentLogger, reuploadRequest: targetSock?.updateMediaMessage }
        );

        if (buffer.length > MAX_MEDIA_BYTES) return { error: 'too_large' };

        return {
            base64: buffer.toString('base64'),
            mimetype: node.mimetype || null,
        };
    } catch (error) {
        console.error(`Failed to download incoming ${mediaType}:`, error.message);
        return { error: 'download_failed' };
    }
}

/** Default mimetypes for outgoing media when the caller doesn't supply one. */
function defaultMimetype(mediaType, isVoiceNote) {
    if (mediaType === 'audio') return isVoiceNote ? 'audio/ogg; codecs=opus' : 'audio/mpeg';
    if (mediaType === 'video') return 'video/mp4';
    if (mediaType === 'image') return 'image/jpeg';
    if (mediaType === 'sticker') return 'image/webp';
    return 'application/octet-stream';
}

/**
 * Convert an audio buffer or URL to an OPUS-encoded OGG buffer in memory for WhatsApp PTT voice notes.
 */
function convertToOpusVoiceNote(input) {
    return new Promise((resolve, reject) => {
        const inSource = Buffer.isBuffer(input) ? Readable.from(input) : input;
        const outStream = new PassThrough();
        const chunks = [];

        outStream.on('data', chunk => chunks.push(chunk));
        outStream.on('end', () => resolve(Buffer.concat(chunks)));
        outStream.on('error', reject);

        ffmpeg(inSource)
            .noVideo()
            .audioCodec('libopus')
            .audioChannels(1)
            .audioFrequency(48000)
            .audioBitrate('48k')
            .format('ogg')
            .outputOptions(['-avoid_negative_ts make_zero'])
            .on('error', err => reject(new Error(`FFmpeg voice note conversion failed: ${err.message}`)))
            .pipe(outStream, { end: true });
    });
}

function withTimeout(promise, ms) {
    return Promise.race([
        promise,
        new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), ms)),
    ]);
}

/**
 * Map Baileys' proto.WebMessageInfo.Status (number or enum name) to the CRM status.
 * ERROR=0, PENDING=1, SERVER_ACK=2, DELIVERY_ACK=3, READ=4, PLAYED=5
 */
function mapReceiptStatus(status) {
    const names = ['ERROR', 'PENDING', 'SERVER_ACK', 'DELIVERY_ACK', 'READ', 'PLAYED'];
    const name = typeof status === 'number' ? names[status] : String(status || '').toUpperCase();

    switch (name) {
        case 'ERROR': return 'failed';
        case 'SERVER_ACK': return 'sent';
        case 'DELIVERY_ACK': return 'delivered';
        case 'READ':
        case 'PLAYED': return 'read';
        default: return null; // PENDING / unknown: nothing to report
    }
}

/** Convert any timestamp (number, Long, or string) strictly to raw UNIX epoch integer seconds. */
function toEpochSeconds(value) {
    if (!value) return Math.floor(Date.now() / 1000);
    const n = Number(value?.low ?? value);
    if (!n || isNaN(n)) return Math.floor(Date.now() / 1000);
    return n > 1e12 ? Math.floor(n / 1000) : Math.floor(n);
}

// ── LRU Cache with TTL support and maximum capacity bounds ──
class LRUCache {
    constructor(maxSize = 1000, defaultTtlMs = null) {
        this.maxSize = maxSize;
        this.defaultTtlMs = defaultTtlMs;
        this.cache = new Map();
    }

    get(key) {
        if (!this.cache.has(key)) return undefined;
        const entry = this.cache.get(key);
        if (entry.expiry && Date.now() > entry.expiry) {
            this.cache.delete(key);
            return undefined;
        }
        this.cache.delete(key);
        this.cache.set(key, entry);
        return entry.value;
    }

    set(key, value, ttlMs = this.defaultTtlMs) {
        if (this.cache.has(key)) {
            this.cache.delete(key);
        } else if (this.cache.size >= this.maxSize) {
            const oldestKey = this.cache.keys().next().value;
            this.cache.delete(oldestKey);
        }
        const expiry = ttlMs ? Date.now() + ttlMs : null;
        this.cache.set(key, { value, expiry });
    }

    has(key) {
        return this.get(key) !== undefined;
    }

    del(key) {
        return this.cache.delete(key);
    }

    delete(key) {
        return this.cache.delete(key);
    }

    clear() {
        this.cache.clear();
    }

    get size() {
        return this.cache.size;
    }

    purgeExpired() {
        const now = Date.now();
        for (const [key, entry] of this.cache.entries()) {
            if (entry.expiry && now > entry.expiry) {
                this.cache.delete(key);
            }
        }
    }
}

// ── Presence & Profile Picture Caches ──
const PRESENCE_RESUBSCRIBE_MS = 10 * 60 * 1000;
const presenceSubscriptions = new LRUCache(1000, PRESENCE_RESUBSCRIBE_MS);
const lastForwardedPresence = new LRUCache(1000, 10000);

async function subscribeToPresence(targetSock, jid, userId = 'default') {
    if (!targetSock) return;
    const cacheKey = `${userId}:${jid}`;
    const last = presenceSubscriptions.get(cacheKey);
    if (last && Date.now() - last < PRESENCE_RESUBSCRIBE_MS) return;

    try {
        await targetSock.presenceSubscribe(jid);
        presenceSubscriptions.set(cacheKey, Date.now(), PRESENCE_RESUBSCRIBE_MS);
    } catch (error) {
        console.error(`presenceSubscribe failed for ${jid}:`, error.message);
    }
}

const isJidIgnored = (jid) => {
    if (!jid || typeof jid !== 'string') return true;
    const clean = jid.trim();
    return clean === 'status@broadcast' || clean.endsWith('@broadcast') || clean.endsWith('@newsletter') || clean.endsWith('@lid');
};

const AVATAR_TTL_FOUND_MS = 60 * 60 * 1000;
const AVATAR_TTL_MISSING_MS = 15 * 60 * 1000;
const avatarCache = new LRUCache(1000);
const groupMetadataCache = new LRUCache(500, 15 * 60 * 1000);
const sharedMsgRetryCache = new LRUCache(1000, 60 * 60 * 1000);

async function fetchProfilePicture(targetSock, jid, resolvedPhone = null) {
    if (!targetSock || !jid || isJidIgnored(jid)) {
        return null;
    }

    const isGroup = jid.endsWith('@g.us');
    const digits = (!isGroup && resolvedPhone)
        ? String(resolvedPhone).replace(/\D/g, '')
        : (!isGroup && jid.includes('@s.whatsapp.net'))
            ? jid.split('@')[0].split(':')[0].replace(/\D/g, '')
            : '';
    const canonicalJid = (!isGroup && digits) ? `${digits}@s.whatsapp.net` : jid;

    const cached = avatarCache.get(canonicalJid) ?? avatarCache.get(jid);
    if (cached !== undefined) {
        return cached;
    }

    let avatarUrl = null;
    const primaryTarget = canonicalJid || jid;
    try {
        avatarUrl = await withTimeout(targetSock.profilePictureUrl(primaryTarget, 'image'), 5000);
    } catch (err) {
        avatarUrl = null;
    }

    if (!avatarUrl && jid !== primaryTarget) {
        try {
            avatarUrl = await withTimeout(targetSock.profilePictureUrl(jid, 'image'), 5000);
        } catch (err) {
            avatarUrl = null;
        }
    }

    const ttl = avatarUrl ? AVATAR_TTL_FOUND_MS : AVATAR_TTL_MISSING_MS;
    avatarCache.set(canonicalJid, avatarUrl || null, ttl);
    if (jid !== canonicalJid) {
        avatarCache.set(jid, avatarUrl || null, ttl);
    }
    return avatarUrl || null;
}

setInterval(() => {
    presenceSubscriptions.purgeExpired();
    lastForwardedPresence.purgeExpired();
    avatarCache.purgeExpired();
    groupMetadataCache.purgeExpired();
    sharedMsgRetryCache.purgeExpired();
}, 5 * 60 * 1000).unref();

/**
 * Resolve a WhatsApp @lid JID to its standard phone number digits (e.g. "+201061701474")
 * using message key fields, Baileys signalRepository, or session authFolder/lid-mapping-*_reverse.json.
 */
async function resolvePhoneFromJid(jid, msg = null, targetSock = null, targetAuthFolder = null) {
    if (!jid) return null;
    if (jid === 'status@broadcast' || jid.endsWith('@broadcast') || jid.endsWith('@newsletter') || jid.endsWith('@g.us')) {
        return null;
    }

    // If jid is already a standard phone JID (@s.whatsapp.net or @c.us), extract digits directly from jid
    if (jid.endsWith('@s.whatsapp.net') || jid.endsWith('@c.us')) {
        const digits = jid.split('@')[0].split(':')[0].replace(/\D/g, '');
        if (digits) return `+${digits}`;
    }

    // Only use participantPn when resolving the participant JID, NEVER when resolving remoteJid
    const isParticipantLookup = Boolean(msg?.key?.participant && jid === msg.key.participant);
    const altCandidates = isParticipantLookup
        ? [msg?.key?.participantPn, msg?.participantPn].filter(Boolean)
        : [
            msg?.key?.remoteJidAlt,
            (!msg?.key?.remoteJid?.endsWith('@g.us') ? msg?.key?.senderPn : null),
        ].filter(Boolean);

    for (const candidate of altCandidates) {
        if (typeof candidate === 'string' && !candidate.endsWith('@lid') && !candidate.endsWith('@g.us')) {
            const digits = candidate.split('@')[0].split(':')[0].replace(/\D/g, '');
            if (digits) return `+${digits}`;
        }
    }

    if (jid.endsWith('@lid')) {
        const lidId = jid.split('@')[0].split(':')[0].replace(/\D/g, '');

        try {
            const pnJid = await targetSock?.signalRepository?.lidMapping?.getPNForLID?.(jid);
            if (pnJid) {
                const digits = String(pnJid).split('@')[0].split(':')[0].replace(/\D/g, '');
                if (digits) return `+${digits}`;
            }
        } catch (_) {}

        if (lidId) {
            // 1. MySQL auth state (key "lid-mapping-<lid>_reverse" of this session)
            const sessionIdForLookup = sessionIdFromAuthFolder(targetAuthFolder);
            if (sessionIdForLookup) {
                try {
                    const mapped = await authStore.readKey(sessionIdForLookup, `lid-mapping-${lidId}_reverse`);
                    const digits = String(mapped ?? '').replace(/\D/g, '');
                    if (digits) return `+${digits}`;
                } catch (_) {}
            }

            // 2. Legacy on-disk auth folders (sessions that were not migrated yet)
            const foldersToCheck = [targetAuthFolder, legacyAuthFolder].filter(Boolean);
            for (const folder of foldersToCheck) {
                const reverseFile = path.join(folder, `lid-mapping-${lidId}_reverse.json`);
                if (fs.existsSync(reverseFile)) {
                    try {
                        const mapped = JSON.parse(fs.readFileSync(reverseFile, 'utf8'));
                        const digits = String(mapped).replace(/\D/g, '');
                        if (digits) return `+${digits}`;
                    } catch (_) {}
                }
            }
        }
    }

    return null;
}

// ============================================================================
// Multi-Session Manager (Stores { [userId]: SessionState } in a Map)
// ============================================================================
class SessionManager {
    constructor() {
        /** @type {Map<string, object>} */
        this.sessions = new Map();
    }

    normalizeKey(userId) {
        if (userId === undefined || userId === null || String(userId).trim() === '') {
            return 'default';
        }
        return String(userId).trim().replace(/^user_/, '');
    }

    getAuthFolder(key) {
        if (key === 'default') {
            return legacyAuthFolder;
        }
        return path.join(sessionsRootDir, `user_${key}`);
    }

    getContactsCachePath(key) {
        const authFolder = this.getAuthFolder(key);
        if (!fs.existsSync(authFolder)) {
            try { fs.mkdirSync(authFolder, { recursive: true }); } catch (_) {}
        }
        return path.join(authFolder, 'contacts_cache.json');
    }

    loadCachedContacts(key) {
        try {
            const filePath = this.getContactsCachePath(key);
            if (fs.existsSync(filePath)) {
                const raw = fs.readFileSync(filePath, 'utf8');
                return JSON.parse(raw) || {};
            }
        } catch (e) {
            console.warn(`[user_${key}] Error reading contacts cache:`, e.message);
        }
        return {};
    }

    saveCachedContacts(key, newContacts) {
        if (!Array.isArray(newContacts) || newContacts.length === 0) return;
        try {
            const cache = this.loadCachedContacts(key);
            let updated = false;
            for (const c of newContacts) {
                const id = c?.id || c?.jid;
                if (!id || isJidIgnored(id) || id.endsWith('@g.us')) continue;

                const existing = cache[id] || {};
                const name = c.name || existing.name || null;
                const notify = c.notify || existing.notify || null;
                const verifiedName = c.verifiedName || existing.verifiedName || null;
                const imgUrl = c.imgUrl || existing.imgUrl || null;

                cache[id] = {
                    id,
                    name,
                    notify,
                    verifiedName,
                    imgUrl,
                    isGroup: false,
                    updatedAt: Date.now(),
                };
                updated = true;
            }

            if (updated) {
                const filePath = this.getContactsCachePath(key);
                fs.writeFileSync(filePath, JSON.stringify(cache, null, 2), 'utf8');
            }
        } catch (e) {
            console.warn(`[user_${key}] Error saving contacts cache:`, e.message);
        }
    }

    getSession(userId) {
        const key = this.normalizeKey(userId);
        return this.sessions.get(key) || null;
    }

    /**
     * Find the active socket for sending/actions:
     * 1. When `userId` is explicitly provided, STRICTLY resolve only that user's connected session
     *    (never fall back to another agent's or team leader's WhatsApp session).
     * 2. When `userId` is omitted/null, fall back to `default` or any connected session.
     */
    resolveActiveSession(userId = null) {
        if (userId !== undefined && userId !== null && String(userId).trim() !== '') {
            const session = this.getSession(userId);
            if (!session || !session.sock) {
                return null;
            }
            const socketReady = session.sock.ws?.readyState === 1 || isSocketOpen(session.sock);
            if (session.status === 'connected' || (socketReady && !session.qr)) {
                return session;
            }
            return null;
        }

        const defaultSession = this.sessions.get('default');
        if (defaultSession && defaultSession.status === 'connected' && defaultSession.sock) {
            return defaultSession;
        }

        for (const session of this.sessions.values()) {
            if (session.status === 'connected' && session.sock) {
                return session;
            }
        }

        return null;
    }

    notifyWaiters(session) {
        if (!session.waiters || session.waiters.length === 0) return;
        const waiters = session.waiters.splice(0, session.waiters.length);
        for (const resolve of waiters) {
            try {
                resolve(session);
            } catch (_) {}
        }
    }

    waitForQrOrOpen(session, timeoutMs = 4500) {
        if (session.status === 'connected' || (session.status === 'qr_ready' && session.qr)) {
            return Promise.resolve(session);
        }
        return new Promise((resolve) => {
            const timer = setTimeout(() => {
                session.waiters = (session.waiters || []).filter(w => w !== onReady);
                resolve(session);
            }, timeoutMs);

            const onReady = (s) => {
                clearTimeout(timer);
                resolve(s);
            };

            session.waiters = session.waiters || [];
            session.waiters.push(onReady);
        });
    }

    async initSession(userId, options = { waitForQrMs: 0 }) {
        const key = this.normalizeKey(userId);
        const authFolder = this.getAuthFolder(key);

        let session = this.sessions.get(key);
        if (session && session.initPromise) {
            await session.initPromise;
            if (options.waitForQrMs > 0) {
                await this.waitForQrOrOpen(session, options.waitForQrMs);
            }
            return session;
        }

        if (session && session.sock && (session.status === 'connected' || session.status === 'qr_ready' || session.status === 'connecting')) {
            if (options.waitForQrMs > 0) {
                await this.waitForQrOrOpen(session, options.waitForQrMs);
            }
            return session;
        }

        // Auth state is stored in MySQL (wa_auth_states) - no on-disk session folder is created anymore

        if (!session) {
            session = {
                userId: key,
                sessionId: key === 'default' ? 'default' : `user_${key}`,
                authFolder,
                sock: null,
                status: 'connecting',
                qr: null,
                credsMe: null,
                lastDisconnect: null,
                isRestarting: false,
                initPromise: null,
                waiters: [],
                startedAt: Date.now(),
            };
            this.sessions.set(key, session);
        } else {
            session.status = 'connecting';
            session.authFolder = authFolder;
        }

        const markConnected = (activeSock) => {
            if (session.sock && session.sock !== activeSock) return;
            const wasConnected = session.status === 'connected';
            session.status = 'connected';
            session.qr = null;
            session.lastDisconnect = null;
            this.notifyWaiters(session);

            if (!wasConnected) {
                const account = getAccountInfo(activeSock, { me: session.credsMe });
                if (account.phone) {
                    session.phone = account.phone;
                }
                console.log(`[${session.sessionId}] WhatsApp session connected (${account.phone || 'ready'})!`);
                if (key !== 'default') {
                    forwardToLaravel({
                        event: 'session.status',
                        status: 'connected',
                        whatsapp_status: 'connected',
                        whatsapp_session_id: session.sessionId,
                        whatsapp_number: account.phone,
                        account,
                    }, 'session.status', 5000, key);
                }
            }
        };

        session.initPromise = (async () => {
            try {
                // MySQL auth state; imports a legacy ./sessions/user_X folder into the DB once
                const { state, saveCreds } = await authStore.useMySQLAuthState(session.sessionId, {
                    legacyFolder: authFolder,
                });
                if (state?.creds?.me?.id) {
                    session.credsMe = state.creds.me;
                }

                const sock = makeWASocket({
                    auth: state,
                    printQRInTerminal: false,
                    syncFullHistory: false,
                    markOnlineOnConnect: false,
                    shouldSyncHistoryMessage: (historyMsg) => {
                        const syncType = historyMsg?.syncType;
                        // Strictly skip FULL (2) and ON_DEMAND (6) historical archives so Baileys does not decompress 50+ history chunks into memory
                        if (
                            syncType === proto?.HistorySync?.HistorySyncType?.FULL ||
                            syncType === proto?.HistorySync?.HistorySyncType?.ON_DEMAND ||
                            syncType === 2 ||
                            syncType === 6
                        ) {
                            return false;
                        }
                        // Allow lightweight INITIAL_BOOTSTRAP (0), RECENT (3), and PUSH_NAME (4) for contacts & chats
                        return (
                            syncType === proto?.HistorySync?.HistorySyncType?.INITIAL_BOOTSTRAP ||
                            syncType === proto?.HistorySync?.HistorySyncType?.RECENT ||
                            syncType === proto?.HistorySync?.HistorySyncType?.PUSH_NAME ||
                            syncType === 0 ||
                            syncType === 3 ||
                            syncType === 4
                        );
                    },
                    msgRetryCounterCache: sharedMsgRetryCache,
                    cachedGroupMetadata: async (jid) => groupMetadataCache.get(jid),
                });

                if (sock.authState && !sock.authState.state) {
                    sock.authState.state = state;
                }

                if (sock.ws && !('readyState' in sock.ws)) {
                    Object.defineProperty(sock.ws, 'readyState', {
                        get() {
                            if (this.socket && typeof this.socket.readyState === 'number') {
                                return this.socket.readyState;
                            }
                            return this.isOpen ? 1 : 0;
                        },
                        configurable: true,
                    });
                }

                session.sock = sock;

                // Immediately mark connected when WhatsApp emits CB:success (before slow pre-key/digest queries)
                if (sock.ws && typeof sock.ws.on === 'function') {
                    sock.ws.on('CB:success', () => {
                        markConnected(sock);
                    });
                }

                sock.ev.on('creds.update', async (credsUpdate) => {
                    if (credsUpdate?.me?.id) {
                        session.credsMe = { ...(session.credsMe || {}), ...credsUpdate.me };
                    }
                    try {
                        await saveCreds();
                    } catch (err) {
                        console.warn(`[${session.sessionId}] Failed to save creds:`, err.message);
                    }
                });

                sock.ev.on('connection.update', async (update) => {
                    if (session.sock && session.sock !== sock) {
                        return;
                    }

                    const { connection, lastDisconnect, qr, receivedPendingNotifications } = update;

                    if (qr) {
                        console.log(`[${session.sessionId}] QR code generated for user ${key}:`);
                        qrcode.generate(qr, { small: true });
                        session.qr = generateQrSvgDataUri(qr);
                        session.status = 'qr_ready';
                        this.notifyWaiters(session);

                        if (key !== 'default') {
                            forwardToLaravel({
                                event: 'session.status',
                                status: 'qr_ready',
                                whatsapp_status: 'qr_ready',
                                whatsapp_session_id: session.sessionId,
                                whatsapp_number: null,
                            }, 'session.status', 5000, key);
                        }
                    }

                    if (connection === 'open' || (receivedPendingNotifications && isSocketOpen(sock))) {
                        markConnected(sock);
                    } else if (connection === 'connecting') {
                        if (isSocketOpen(sock) && (sock.user?.id || state?.creds?.me?.id) && !session.qr) {
                            markConnected(sock);
                        } else if (session.status !== 'qr_ready' && session.status !== 'connected') {
                            session.status = 'connecting';
                        }
                    } else if (connection === 'close') {
                        const statusCode = lastDisconnect?.error?.output?.statusCode;
                        const shouldReconnect = statusCode !== DisconnectReason.loggedOut && !session.isRestarting;
                        session.lastDisconnect = lastDisconnect?.error?.message || `Status: ${statusCode || 'unknown'}`;
                        session.qr = null;

                        if (statusCode === DisconnectReason.loggedOut) {
                            session.status = 'disconnected';
                            session.sock = null;
                            session.credsMe = null;
                            this.notifyWaiters(session);

                            // Clean up invalidated auth credentials so a fresh QR can be generated cleanly
                            authStore.removeSession(session.sessionId).catch((err) =>
                                console.warn(`[${session.sessionId}] Failed to delete auth state from MySQL:`, err.message)
                            );
                            // Also drop any legacy on-disk copy, otherwise it would be re-imported on next boot
                            if (fs.existsSync(authFolder)) {
                                try {
                                    fs.rmSync(authFolder, { recursive: true, force: true });
                                } catch (_) {}
                            }

                            if (key !== 'default') {
                                forwardToLaravel({
                                    event: 'session.status',
                                    status: 'disconnected',
                                    whatsapp_status: 'disconnected',
                                    whatsapp_session_id: session.sessionId,
                                    whatsapp_number: null,
                                }, 'session.status', 5000, key);
                            }
                        } else {
                            session.status = 'connecting';
                        }

                        console.log(
                            `[${session.sessionId}] Connection closed due to:`,
                            lastDisconnect?.error?.message || statusCode,
                            '| Reconnecting:',
                            shouldReconnect
                        );

                        if (shouldReconnect) {
                            session.sock = null;
                            setTimeout(() => {
                                if (!session.isRestarting) {
                                    this.initSession(key).catch(err =>
                                        console.error(`[${session.sessionId}] Reconnect failed:`, err.message)
                                    );
                                }
                            }, 1500);
                        }
                    }
                });

                // Listen for incoming messages on this user's socket
                sock.ev.on('messages.upsert', async (event) => {
                    if (session.status !== 'connected' && (!session.sock || session.sock === sock)) {
                        markConnected(sock);
                    }
                    for (const msg of event.messages) {
                if (msg.message) {
                    const content = normalizeMessageContent(msg.message) || msg.message || {};
                    const msgType = Object.keys(content || {})[0] || Object.keys(msg.message || {})[0];

                    // Drop silent system/encryption/protocol messages (including nested in ephemeralMessage)
                    if (
                        msgType === 'senderKeyDistributionMessage' ||
                        msgType === 'protocolMessage' ||
                        msgType === 'messageContextInfo'
                    ) {
                        const prot = content.protocolMessage || msg.message?.protocolMessage;
                        const isRevokeOrEdit = prot && (
                            prot.type === 0 ||
                            prot.type === 'REVOKE' ||
                            prot.type === 14 ||
                            prot.type === 'MESSAGE_EDIT' ||
                            Boolean(prot.editedMessage)
                        );

                        if (!isRevokeOrEdit) {
                            continue; // Drop silent system/encryption messages
                        }
                    }

                    if ((content.senderKeyDistributionMessage || msg.message?.senderKeyDistributionMessage) && !content.conversation && !content.extendedTextMessage && !content.imageMessage && !content.videoMessage && !content.audioMessage && !content.documentMessage && !content.stickerMessage && !content.contactMessage && !content.contactsArrayMessage) {
                        continue;
                    }

                    const isFromMe = Boolean(msg.key?.fromMe);
                    const remoteJid = msg.key.remoteJid;

                    // Ignore WhatsApp Statuses (Stories), broadcast lists, and Channels (@newsletter) immediately
                    if (!remoteJid || remoteJid === 'status@broadcast' || remoteJid.endsWith('@broadcast') || remoteJid.endsWith('@newsletter')) {
                        continue;
                    }

                    const sender = remoteJid;
                    const isGroup = remoteJid.endsWith('@g.us');
                    let groupName = null;
                    let participant = msg.key.participant || remoteJid; // The actual person who sent it

                    if (isGroup) {
                        const resolvedParticipant = await resolvePhoneFromJid(participant, msg, sock, authFolder);
                        if (resolvedParticipant) {
                            participant = resolvedParticipant;
                        } else if (participant && participant.includes('@')) {
                            const pDigits = participant.split('@')[0].split(':')[0].replace(/\D/g, '');
                            if (pDigits) participant = `+${pDigits}`;
                        }

                        const cachedGroupName = groupMetadataCache.get(remoteJid);
                        if (cachedGroupName) {
                            groupName = cachedGroupName;
                        } else {
                            try {
                                const metadata = await withTimeout(sock.groupMetadata(remoteJid), 4000);
                                groupName = metadata?.subject || 'WhatsApp Group';
                                if (metadata?.subject) {
                                    groupMetadataCache.set(remoteJid, metadata.subject, 15 * 60 * 1000);
                                }
                            } catch (err) {
                                console.error('Failed to fetch group metadata', err.message || err);
                                groupName = 'WhatsApp Group';
                            }
                        }
                    }

                    // 1. Incoming / Outbound reaction
                    const reactionMsg = content.reactionMessage || msg.message?.reactionMessage || content.encReactionMessage || msg.message?.encReactionMessage;
                    if (reactionMsg) {
                        const targetKey = reactionMsg.key;
                        const emoji = reactionMsg.text || '';
                        const resolvedPhone = isGroup ? null : await resolvePhoneFromJid(sender, msg, sock, authFolder);

                        console.log(`[${session.sessionId}] Reaction received: "${emoji || '[removed]'}" for message ${targetKey?.id} from ${sender}`);

                        await forwardToLaravel({
                            event: 'reaction',
                            from: isGroup ? remoteJid : (resolvedPhone || sender),
                            phone: isGroup ? remoteJid : (resolvedPhone || sender),
                            remoteJid: remoteJid,
                            resolved_phone: resolvedPhone,
                            isGroup,
                            groupName,
                            participant: isGroup ? participant : (resolvedPhone || sender),
                            target_id: targetKey?.id || null,
                            target_key: targetKey || null,
                            emoji,
                            key: msg.key,
                            is_from_me: isFromMe,
                            fromMe: isFromMe,
                            direction: isFromMe ? 'out' : 'in',
                            timestamp: toEpochSeconds(msg.messageTimestamp),
                        }, 'reaction', 5000, key);
                        continue;
                    }

                    // 2. Incoming / Outbound message revocation (delete for everyone)
                    if (content.protocolMessage && (content.protocolMessage.type === 0 || content.protocolMessage.type === 'REVOKE')) {
                        const targetKey = content.protocolMessage.key;
                        const resolvedPhone = isGroup ? null : await resolvePhoneFromJid(sender, msg, sock, authFolder);

                        await forwardToLaravel({
                            event: 'message.delete',
                            target_id: targetKey?.id || null,
                            target_key: targetKey || null,
                            remoteJid: sender,
                            from: isGroup ? remoteJid : (resolvedPhone || sender),
                            phone: isGroup ? remoteJid : (resolvedPhone || sender),
                            isGroup,
                            groupName,
                            participant: isGroup ? participant : (resolvedPhone || sender),
                            key: msg.key,
                            is_from_me: isFromMe,
                            fromMe: isFromMe,
                            direction: isFromMe ? 'out' : 'in',
                            timestamp: toEpochSeconds(msg.messageTimestamp),
                        }, 'message.delete', 5000, key);
                        continue;
                    }

                    // 3. Incoming / Outbound edited message
                    const editedNode = content.protocolMessage?.editedMessage || content.editedMessage;
                    if (editedNode || (content.protocolMessage && (content.protocolMessage.type === 14 || content.protocolMessage.type === 'MESSAGE_EDIT'))) {
                        const targetKey = content.protocolMessage?.key || msg.key;
                        const unwrappedEdited = normalizeMessageContent(editedNode) || editedNode;
                        const newText =
                            unwrappedEdited?.conversation ||
                            unwrappedEdited?.extendedTextMessage?.text ||
                            '';
                        const resolvedPhone = isGroup ? null : await resolvePhoneFromJid(sender, msg, sock, authFolder);

                        await forwardToLaravel({
                            event: 'message.edit',
                            target_id: targetKey?.id || null,
                            target_key: targetKey || null,
                            new_text: newText,
                            remoteJid: sender,
                            from: isGroup ? remoteJid : (resolvedPhone || sender),
                            phone: isGroup ? remoteJid : (resolvedPhone || sender),
                            isGroup,
                            groupName,
                            participant: isGroup ? participant : (resolvedPhone || sender),
                            key: msg.key,
                            is_from_me: isFromMe,
                            fromMe: isFromMe,
                            direction: isFromMe ? 'out' : 'in',
                            timestamp: toEpochSeconds(msg.messageTimestamp),
                        }, 'message.edit', 5000, key);
                        continue;
                    }

                    const mediaInfo = detectIncomingMedia(content);
                    const contactInfo = !mediaInfo ? extractIncomingContacts(content) : null;
                    const text = contactInfo
                        ? JSON.stringify({ type: 'vcard_contacts', contacts: contactInfo.contacts })
                        : (
                            content.conversation ||
                            content.extendedTextMessage?.text ||
                            mediaInfo?.node?.caption ||
                            ''
                        ).trim();

                    // Safety fallback: if extracted text body is empty, dot, or null AND there is no valid media/contact attached, drop entirely
                    if (!sender || (!mediaInfo && !contactInfo && (!text || text === '.' || text === 'null'))) {
                        continue;
                    }

                    const contextInfo =
                        content?.extendedTextMessage?.contextInfo ||
                        content?.imageMessage?.contextInfo ||
                        content?.videoMessage?.contextInfo ||
                        content?.audioMessage?.contextInfo ||
                        content?.documentMessage?.contextInfo ||
                        content?.stickerMessage?.contextInfo ||
                        contactInfo?.contextInfo ||
                        content?.contextInfo;

                    const quotedWaId = contextInfo?.stanzaId || null;
                    const resolvedPhone = isGroup ? null : await resolvePhoneFromJid(sender, msg, sock, authFolder);
                    if (!isGroup && resolvedPhone) {
                        participant = resolvedPhone;
                    }

                    console.log(
                        `[${session.sessionId}] ${isFromMe ? 'Outbound' : 'Incoming'} ${mediaInfo ? mediaInfo.mediaType : 'message'} ${isFromMe ? 'to' : 'from'} ${sender} ` +
                        `(${isGroup ? `group: "${groupName}", participant: ${participant}` : `resolved: ${resolvedPhone || 'N/A'}`}${quotedWaId ? ', replying to ' + quotedWaId : ''}): ${text || '[no text]'}`
                    );

                    let avatarUrl = null;
                    const [, media] = await Promise.all([
                        fetchProfilePicture(sock, remoteJid, resolvedPhone).then(url => {
                            avatarUrl = url;
                        }).catch(() => {
                            avatarUrl = null;
                        }),
                        mediaInfo ? downloadIncomingMedia(sock, msg, mediaInfo) : null,
                        isGroup ? null : subscribeToPresence(sock, sender, key),
                    ]);

                    const payload = {
                        event: 'messages.upsert',
                        from: isGroup ? remoteJid : (resolvedPhone || sender),
                        phone: isGroup ? remoteJid : (resolvedPhone || sender),
                        remoteJid: sender,
                        resolved_phone: resolvedPhone,
                        isGroup,
                        groupName,
                        participant: isFromMe ? (session.phone || `user_${key}`) : participant,
                        is_from_me: isFromMe,
                        fromMe: isFromMe,
                        direction: isFromMe ? 'out' : 'in',
                        message: text,
                        pushName: isFromMe ? null : (msg.pushName || null),
                        avatarUrl: avatarUrl || null,
                        avatar_url: avatarUrl || null,
                        quoted_wa_id: quotedWaId,
                        key: msg.key,
                        timestamp: toEpochSeconds(msg.messageTimestamp),
                        data: {
                            key: msg.key,
                            is_from_me: isFromMe,
                            fromMe: isFromMe,
                            direction: isFromMe ? 'out' : 'in',
                            pushName: isFromMe ? null : (msg.pushName || null),
                            messageTimestamp: toEpochSeconds(msg.messageTimestamp),
                            message: text,
                            isGroup,
                            groupName,
                            participant: isFromMe ? (session.phone || `user_${key}`) : participant,
                            avatarUrl: avatarUrl || null,
                            avatar_url: avatarUrl || null,
                        },
                    };

                    if (mediaInfo) {
                        const isSticker = mediaInfo.mediaType === 'sticker';
                        Object.assign(payload, {
                            mediaType: mediaInfo.mediaType,
                            mimetype: media?.mimetype || mediaInfo.node.mimetype || (isSticker ? 'image/webp' : null),
                            fileName: mediaInfo.node.fileName || (isSticker ? 'sticker.webp' : null),
                            is_voice_note: mediaInfo.mediaType === 'audio' && !!mediaInfo.node.ptt,
                            is_animated: isSticker && !!mediaInfo.node.isAnimated,
                            media_base64: media?.base64 || null,
                            media_error: media?.error || null,
                        });
                    } else if (contactInfo) {
                        Object.assign(payload, {
                            mediaType: 'contact',
                            mimetype: 'text/vcard',
                            fileName: contactInfo.displayName,
                            contacts: contactInfo.contacts,
                        });
                    } else {
                        payload.raw = msg;
                    }

                    await forwardToLaravel(payload, mediaInfo ? 'media message' : 'messages.upsert', mediaInfo ? 30000 : 5000, key);
                }
            }
        });


        // Sync contacts and names from WhatsApp address book
        sock.ev.on('contacts.upsert', async (rawContacts) => {
            try {
                const cleanContacts = [];
                for (const c of (rawContacts || [])) {
                    const jid = c?.id || c?.jid;
                    if (!jid || isJidIgnored(jid) || jid.endsWith('@g.us')) continue;
                    cleanContacts.push({
                        id: jid,
                        name: c.name || null,
                        notify: c.notify || c.verifiedName || null,
                        verifiedName: c.verifiedName || null,
                        imgUrl: c.imgUrl || null,
                        isGroup: false,
                    });
                }
                if (cleanContacts.length > 0) {
                    this.saveCachedContacts(key, cleanContacts);
                    await forwardToLaravel({
                        event: 'contacts.upsert',
                        contacts: cleanContacts,
                        user_id: key,
                        session_id: session.sessionId,
                    }, 'contacts.upsert', 10000, key);
                }
            } catch (err) {
                console.error(`[${session.sessionId}] Error handling contacts.upsert:`, err?.message || err);
            }
        });


        sock.ev.on('contacts.update', async (updates) => {
            try {
                const cleanUpdates = [];
                for (const u of (updates || [])) {
                    const jid = u?.id || u?.jid;
                    if (!jid || isJidIgnored(jid) || jid.endsWith('@g.us')) continue;
                    cleanUpdates.push({
                        id: jid,
                        name: u.name || null,
                        notify: u.notify || u.verifiedName || null,
                        verifiedName: u.verifiedName || null,
                        imgUrl: u.imgUrl || null,
                        isGroup: false,
                    });
                }
                if (cleanUpdates.length > 0) {
                    this.saveCachedContacts(key, cleanUpdates);
                    await forwardToLaravel({
                        event: 'contacts.update',
                        contacts: cleanUpdates,
                        user_id: key,
                        session_id: session.sessionId,
                    }, 'contacts.update', 10000, key);
                }
            } catch (err) {
                console.error(`[${session.sessionId}] Error handling contacts.update:`, err?.message || err);
            }
        });


        // Delivery / read receipts & reaction updates for messages
        sock.ev.on('messages.update', async (updates) => {
            for (const { key: msgKey, update } of updates) {
                if (!msgKey?.id || !update) {
                    continue;
                }

                const jid = msgKey.remoteJid;
                if (!jid || isJidIgnored(jid)) {
                    continue;
                }

                const isGroup = jid.endsWith('@g.us');

                // 1. Reactions dispatch via messages.update
                const reactionsList = update.reactions || (update.reaction ? [update.reaction] : null);
                if (Array.isArray(reactionsList) && reactionsList.length > 0) {
                    const latestReaction = reactionsList[reactionsList.length - 1];
                    const emoji = latestReaction?.text || '';
                    const rKey = latestReaction?.key || {};
                    const isFromMe = rKey.fromMe !== undefined ? Boolean(rKey.fromMe) : false;
                    const participant = rKey.participant || msgKey.participant || jid;
                    const resolvedPhone = isGroup ? null : await resolvePhoneFromJid(jid, { key: msgKey }, sock, authFolder);

                    console.log(`[${session.sessionId}] Reaction update for message ${msgKey.id}: "${emoji || '[removed]'}"`);

                    await forwardToLaravel({
                        event: 'reaction',
                        target_id: msgKey.id,
                        target_key: msgKey,
                        emoji,
                        reactions: reactionsList,
                        remoteJid: jid,
                        from: isGroup ? jid : (resolvedPhone || jid),
                        phone: isGroup ? jid : (resolvedPhone || jid),
                        resolved_phone: resolvedPhone,
                        participant: isGroup ? participant : (resolvedPhone || jid),
                        isGroup,
                        is_from_me: isFromMe,
                        fromMe: isFromMe,
                        direction: isFromMe ? 'out' : 'in',
                        key: rKey.id ? rKey : msgKey,
                        timestamp: Math.floor(Date.now() / 1000),
                    }, 'reaction (update)', 5000, key);
                    continue;
                }

                // 2. Receipts: status updates for outbound messages
                if (!msgKey.fromMe || update.status === undefined || update.status === null) {
                    continue;
                }

                const status = mapReceiptStatus(update.status);
                if (!status) continue;

                const resolvedPhone = isGroup ? null : await resolvePhoneFromJid(jid, { key: msgKey }, sock, authFolder);
                console.log(`[${session.sessionId}] Message ${msgKey.id} to ${jid} is now: ${status}`);

                await forwardToLaravel({
                    event: 'message.status',
                    id: msgKey.id,
                    status,
                    remoteJid: jid,
                    from: isGroup ? jid : (resolvedPhone || jid),
                    phone: isGroup ? jid : (resolvedPhone || jid),
                    resolved_phone: resolvedPhone,
                    isGroup,
                    key: msgKey,
                    timestamp: Math.floor(Date.now() / 1000),
                }, 'message status', 5000, key);
            }
        });

        // Reactions emitted via messages.reaction in Baileys
        sock.ev.on('messages.reaction', async (reactions) => {
            for (const item of (reactions || [])) {
                const targetKey = item?.key;
                const reaction = item?.reaction;
                if (!targetKey?.id) continue;

                const jid = targetKey.remoteJid || reaction?.key?.remoteJid;
                if (!jid || isJidIgnored(jid)) continue;

                const isGroup = jid.endsWith('@g.us');
                const emoji = reaction?.text || '';
                const rKey = reaction?.key || {};
                const isFromMe = rKey.fromMe !== undefined ? Boolean(rKey.fromMe) : false;
                const participant = rKey.participant || targetKey.participant || jid;
                const resolvedPhone = isGroup ? null : await resolvePhoneFromJid(jid, { key: targetKey }, sock, authFolder);

                console.log(`[${session.sessionId}] Reaction (event) for message ${targetKey.id}: "${emoji || '[removed]'}"`);

                await forwardToLaravel({
                    event: 'reaction',
                    target_id: targetKey.id,
                    target_key: targetKey,
                    emoji,
                    reactions: [reaction],
                    remoteJid: jid,
                    from: isGroup ? jid : (resolvedPhone || jid),
                    phone: isGroup ? jid : (resolvedPhone || jid),
                    resolved_phone: resolvedPhone,
                    participant: isGroup ? participant : (resolvedPhone || jid),
                    isGroup,
                    is_from_me: isFromMe,
                    fromMe: isFromMe,
                    direction: isFromMe ? 'out' : 'in',
                    key: rKey.id ? rKey : targetKey,
                    timestamp: Math.floor(Date.now() / 1000),
                }, 'reaction (messages.reaction)', 5000, key);
            }
        });

        // Delivery / read receipts emitted via message-receipt.update in Baileys
        sock.ev.on('message-receipt.update', async (receipts) => {
            for (const item of (receipts || [])) {
                const msgKey = item?.key;
                const receipt = item?.receipt;
                if (!msgKey?.id) continue;

                const jid = msgKey.remoteJid;
                if (!jid || jid === 'status@broadcast' || jid.endsWith('@broadcast') || jid.endsWith('@newsletter')) {
                    continue;
                }

                let status = 'delivered';
                if (receipt?.readTimestamp) {
                    status = 'read';
                }

                const isGroup = jid.endsWith('@g.us');
                const resolvedPhone = isGroup ? null : await resolvePhoneFromJid(jid, { key: msgKey }, sock, authFolder);
                console.log(`[${session.sessionId}] Receipt for ${msgKey.id} to ${jid} is now: ${status}`);

                await forwardToLaravel({
                    event: 'message.status',
                    id: msgKey.id,
                    status,
                    remoteJid: jid,
                    from: isGroup ? jid : (resolvedPhone || jid),
                    phone: isGroup ? jid : (resolvedPhone || jid),
                    resolved_phone: resolvedPhone,
                    isGroup,
                    key: msgKey,
                    timestamp: toEpochSeconds(receipt?.readTimestamp || receipt?.receiptTimestamp || Date.now()),
                }, 'message receipt', 5000, key);
            }
        });


        // Online / typing / last seen of contacts subscribed on this user's socket
        sock.ev.on('presence.update', async ({ id, presences }) => {
            if (!id || id === 'status@broadcast' || id.endsWith('@broadcast') || id.endsWith('@newsletter') || id.endsWith('@g.us')) return;

            for (const [jid, data] of Object.entries(presences || {})) {
                const presence = data?.lastKnownPresence;
                if (!presence) continue;

                const dedupeKey = `${key}:${jid}`;
                const last = lastForwardedPresence.get(dedupeKey);
                if (last && last.presence === presence && Date.now() - last.at < 10000) continue;
                lastForwardedPresence.set(dedupeKey, { presence, at: Date.now() });

                const resolvedPhone = await resolvePhoneFromJid(jid, null, sock, authFolder);

                await forwardToLaravel({
                    event: 'presence',
                    remoteJid: jid,
                    from: resolvedPhone || jid,
                    phone: resolvedPhone || jid,
                    resolved_phone: resolvedPhone,
                    presence,
                    last_seen: data.lastSeen ? toEpochSeconds(data.lastSeen) : null,
                    timestamp: Math.floor(Date.now() / 1000),
                }, 'presence', 5000, key);
            }
        });


        // WhatsApp History Synchronization (messaging-history.set for initial, full, recent, and ON_DEMAND syncs)
        sock.ev.on('messaging-history.set', async (historyPayload = {}) => {
            try {
                const {
                    chats = [],
                    contacts = [],
                    messages = [],
                    lidPnMappings = [],
                    isLatest,
                    progress,
                    syncType,
                } = historyPayload;

                const isFullOrOnDemandSync =
                    syncType === proto?.HistorySync?.HistorySyncType?.FULL ||
                    syncType === proto?.HistorySync?.HistorySyncType?.ON_DEMAND ||
                    syncType === 2 ||
                    syncType === 6 ||
                    syncType === 'FULL' ||
                    syncType === 'ON_DEMAND';

                if (isFullOrOnDemandSync) {
                    console.log(
                        `[${session.sessionId}] Skipping message extraction for FULL/ON_DEMAND history sync (syncType=${syncType}) to preserve memory. ` +
                        `Contacts (${contacts.length}) and chats (${chats.length}) will still be safely processed.`
                    );
                }

                // Helper: Ignore WhatsApp Statuses (Stories), broadcast lists, and Channels (@newsletter)
                const isBroadcastOrNewsletter = (jid) => {
                    if (!jid || typeof jid !== 'string') return true;
                    const clean = jid.trim();
                    return clean === 'status@broadcast' || clean.endsWith('@broadcast') || clean.endsWith('@newsletter');
                };

                // Build an in-batch LID -> Phone JID map from lidPnMappings, chats, and contacts
                const lidToPnJid = new Map();
                const registerLidPn = (lidCandidate, pnCandidate) => {
                    if (!lidCandidate || !pnCandidate) return;
                    const lidStr = String(lidCandidate).trim();
                    const pnStr = String(pnCandidate).trim();
                    if (!lidStr.endsWith('@lid')) return;
                    const digits = pnStr.split('@')[0].split(':')[0].replace(/\D/g, '');
                    if (!digits) return;
                    const normalizedPnJid = `${digits}@s.whatsapp.net`;
                    lidToPnJid.set(lidStr, normalizedPnJid);
                    const lidBase = lidStr.split('@')[0].split(':')[0].replace(/\D/g, '');
                    if (lidBase) {
                        lidToPnJid.set(`${lidBase}@lid`, normalizedPnJid);
                    }
                };

                for (const m of (lidPnMappings || [])) {
                    registerLidPn(m?.lid || m?.lidJid, m?.pn || m?.pnJid);
                }
                for (const chat of (chats || [])) {
                    const cId = chat?.id || chat?.jid;
                    if (cId && String(cId).endsWith('@lid') && chat?.pnJid) {
                        registerLidPn(cId, chat.pnJid);
                    } else if (chat?.lidJid && cId && !String(cId).endsWith('@lid')) {
                        registerLidPn(chat.lidJid, cId);
                    }
                }
                for (const contact of (contacts || [])) {
                    const cId = contact?.id || contact?.jid;
                    const pn = contact?.phoneNumber || contact?.pnJid;
                    const lid = contact?.lid || contact?.lidJid || (cId && String(cId).endsWith('@lid') ? cId : null);
                    if (lid && pn) {
                        registerLidPn(lid, pn);
                    } else if (lid && cId && !String(cId).endsWith('@lid')) {
                        registerLidPn(lid, cId);
                    }
                }

                // Resolve a JID (converting @lid to <digits>@s.whatsapp.net whenever possible)
                const normalizeHistoryJid = async (rawJid, msgObj = null) => {
                    if (!rawJid || typeof rawJid !== 'string') return null;
                    const clean = rawJid.trim();
                    if (isBroadcastOrNewsletter(clean)) return null;
                    if (clean.endsWith('@g.us')) return clean;

                    if (clean.endsWith('@lid')) {
                        const lidBase = clean.split('@')[0].split(':')[0].replace(/\D/g, '');
                        const mapped = lidToPnJid.get(clean) || (lidBase ? lidToPnJid.get(`${lidBase}@lid`) : null);
                        if (mapped) return mapped;

                        const resolvedPhone = await resolvePhoneFromJid(clean, msgObj, sock, authFolder);
                        if (resolvedPhone) {
                            const digits = String(resolvedPhone).replace(/\D/g, '');
                            if (digits) {
                                const pnJid = `${digits}@s.whatsapp.net`;
                                registerLidPn(clean, pnJid);
                                return pnJid;
                            }
                        }
                        return null; // Unresolvable @lid
                    }

                    return clean;
                };

                // 1. Process & filter chats (and collect lightweight recent messages if not full sync)
                const cleanChats = [];
                const nestedChatMessages = [];
                for (const chat of (chats || [])) {
                    if (!isFullOrOnDemandSync && Array.isArray(chat?.messages)) {
                        const recentSlice = chat.messages.slice(-5);
                        for (const item of recentSlice) {
                            const m = item?.message || item;
                            if (m && typeof m === 'object') {
                                nestedChatMessages.push(m);
                            }
                        }
                    }

                    const rawChatJid = chat?.pnJid || chat?.id || chat?.jid;
                    const jid = await normalizeHistoryJid(rawChatJid);
                    if (!jid) continue;
                    const isGroup = jid.endsWith('@g.us');
                    cleanChats.push({
                        id: jid,
                        name: chat.name || chat.displayName || (isGroup ? 'WhatsApp Group' : null),
                        unreadCount: typeof chat.unreadCount === 'number' ? chat.unreadCount : 0,
                        isGroup,
                        conversationTimestamp: toEpochSeconds(chat.conversationTimestamp),
                    });
                }

                // 2. Process & filter contacts (Always processed to sync phonebook properly)
                const cleanContacts = [];
                for (const contact of (contacts || [])) {
                    const rawContactJid = contact?.phoneNumber || contact?.pnJid || contact?.id || contact?.jid;
                    const jid = await normalizeHistoryJid(rawContactJid);
                    if (!jid || isJidIgnored(jid) || jid.endsWith('@g.us')) continue;
                    cleanContacts.push({
                        id: jid,
                        name: contact.name || null,
                        notify: contact.notify || contact.verifiedName || null,
                        verifiedName: contact.verifiedName || null,
                        imgUrl: contact.imgUrl || null,
                        isGroup: false,
                    });
                }

                // 3. Collect bounded messages (strictly capped per chat and total; skipped completely for FULL sync)
                const allRawMessages = [];
                if (!isFullOrOnDemandSync) {
                    const seenRawMsgIds = new Set();
                    const messagesPerChat = new Map();
                    const MAX_MSGS_PER_CHAT = 20; // Only keep up to 20 most recent messages per conversation
                    const MAX_TOTAL_HISTORY_MSGS = 300; // Hard cap per history sync payload

                    const rawCandidates = [...(messages || []), ...nestedChatMessages];
                    // Traverse backwards (from newest) to keep the most recent messages
                    for (let idx = rawCandidates.length - 1; idx >= 0; idx--) {
                        if (allRawMessages.length >= MAX_TOTAL_HISTORY_MSGS) break;

                        const candidate = rawCandidates[idx];
                        const msg = candidate?.message && candidate?.key === undefined ? candidate.message : candidate;
                        if (!msg || typeof msg !== 'object') continue;

                        const msgId = msg.key?.id;
                        if (msgId) {
                            if (seenRawMsgIds.has(msgId)) continue;
                            seenRawMsgIds.add(msgId);
                        }

                        const rawRemoteJid = msg.key?.remoteJid || msg.remoteJid;
                        if (rawRemoteJid) {
                            const count = messagesPerChat.get(rawRemoteJid) || 0;
                            if (count >= MAX_MSGS_PER_CHAT) continue;
                            messagesPerChat.set(rawRemoteJid, count + 1);
                        }

                        allRawMessages.push(msg);
                    }
                }

                const extractedMessages = [];
                for (const msg of allRawMessages) {
                    if (!msg?.message) continue;

                    const content = normalizeMessageContent(msg.message) || msg.message || {};
                    const msgType = Object.keys(content || {})[0] || Object.keys(msg.message || {})[0];

                    // Drop silent system/encryption/protocol messages (including nested in ephemeralMessage)
                    if (
                        msgType === 'senderKeyDistributionMessage' ||
                        msgType === 'protocolMessage' ||
                        msgType === 'messageContextInfo'
                    ) {
                        const prot = content.protocolMessage || msg.message?.protocolMessage;
                        const isRevokeOrEdit = prot && (
                            prot.type === 0 ||
                            prot.type === 'REVOKE' ||
                            prot.type === 14 ||
                            prot.type === 'MESSAGE_EDIT' ||
                            Boolean(prot.editedMessage)
                        );

                        if (!isRevokeOrEdit) {
                            continue; // Drop silent system/encryption messages
                        }
                    }

                    if ((content.senderKeyDistributionMessage || msg.message?.senderKeyDistributionMessage) && !content.conversation && !content.extendedTextMessage && !content.imageMessage && !content.videoMessage && !content.audioMessage && !content.documentMessage && !content.stickerMessage && !content.contactMessage && !content.contactsArrayMessage) {
                        continue;
                    }

                    const rawRemoteJid = msg?.key?.remoteJid || msg?.remoteJid;
                    const remoteJid = await normalizeHistoryJid(rawRemoteJid, msg);
                    if (!remoteJid) continue;

                    const isGroup = remoteJid.endsWith('@g.us');
                    const participant = msg.key?.participant || msg.participant || (isGroup ? null : remoteJid);
                    if (isGroup && msg.key) {
                        // Force the message to stay under the unified group JID
                        msg.key.participant = participant;
                    }

                    const ts = toEpochSeconds(msg.messageTimestamp || msg.timestamp);
                    const isFromMe = Boolean(msg.key?.fromMe);
                    const mediaInfo = detectIncomingMedia(content);
                    const contactInfo = !mediaInfo ? extractIncomingContacts(content) : null;

                    const text = contactInfo
                        ? JSON.stringify({ type: 'vcard_contacts', contacts: contactInfo.contacts })
                        : (
                            content?.conversation ||
                            content?.extendedTextMessage?.text ||
                            mediaInfo?.node?.caption ||
                            ''
                        ).trim();

                    // Safety fallback: if extracted text is empty/dot/null AND there is no media/contact, drop message entirely
                    if (!mediaInfo && !contactInfo && (!text || text === '.' || text === 'null')) continue;

                    let body = text;

                    // Memory safety: NEVER buffer full media or base64 thumbnails during history sync
                    if (mediaInfo && !body) {
                        if (mediaInfo.mediaType === 'audio') {
                            body = '🎤 [Voice Note]';
                        } else if (mediaInfo.mediaType === 'document') {
                            body = mediaInfo.node?.fileName ? `📄 [Document: ${mediaInfo.node.fileName}]` : '📄 [Document]';
                        } else if (mediaInfo.mediaType === 'video') {
                            body = '🎥 [Video]';
                        } else if (mediaInfo.mediaType === 'sticker') {
                            body = '🏷️ [Sticker]';
                        } else {
                            body = '📷 [Photo]';
                        }
                    }

                    const contextInfo =
                        content?.extendedTextMessage?.contextInfo ||
                        content?.imageMessage?.contextInfo ||
                        content?.videoMessage?.contextInfo ||
                        content?.audioMessage?.contextInfo ||
                        content?.documentMessage?.contextInfo ||
                        content?.stickerMessage?.contextInfo ||
                        content?.contextInfo;

                    const quotedWaId = contextInfo?.stanzaId || null;

                    extractedMessages.push({
                        key: {
                            id: msg.key?.id,
                            remoteJid,
                            fromMe: isFromMe,
                            participant: isGroup ? participant : remoteJid,
                        },
                        remoteJid,
                        participant: isGroup ? participant : remoteJid,
                        messageTimestamp: ts,
                        timestamp: ts,
                        body,
                        text,
                        is_from_me: isFromMe,
                        fromMe: isFromMe,
                        direction: isFromMe ? 'out' : 'in',
                        status: msg.status || (isFromMe ? 'sent' : 'delivered'),
                        quoted_wa_id: quotedWaId,
                        pushName: (isGroup || isFromMe) ? null : (msg.pushName || null),
                        senderPushName: (isGroup || isFromMe) ? null : (msg.pushName || null),
                        mediaType: mediaInfo?.mediaType || (contactInfo ? 'contact' : null),
                        fileName: mediaInfo?.node?.fileName || contactInfo?.displayName || null,
                        mimetype: mediaInfo?.node?.mimetype || (contactInfo ? 'text/vcard' : null),
                        contacts: contactInfo?.contacts || null,
                        fullMediaBase64: null,
                        media_base64: null,
                        thumbnailBase64: null,
                        isGroup,
                    });
                }

                console.log(
                    `[${session.sessionId}] WhatsApp history sync (type=${syncType ?? 'unknown'}): ${cleanChats.length} chats, ` +
                    `${cleanContacts.length} contacts, ${extractedMessages.length} messages extracted (out of ${allRawMessages.length} candidates)`
                );

                // Ensure extractedMessages are strictly sorted ascending chronologically
                extractedMessages.sort((a, b) => Number(a.messageTimestamp || a.timestamp || 0) - Number(b.messageTimestamp || b.timestamp || 0));

                // 4. Safe Sequential Chunking (100 contacts, 50 messages per chunk) to eliminate OOM
                if (cleanContacts.length > 0) {
                    this.saveCachedContacts(key, cleanContacts);
                    const CONTACT_CHUNK_SIZE = 100;
                    for (let c = 0; c < cleanContacts.length; c += CONTACT_CHUNK_SIZE) {
                        const contactBatch = cleanContacts.slice(c, c + CONTACT_CHUNK_SIZE);
                        try {
                            await forwardToLaravel({
                                event: 'contacts.upsert',
                                contacts: contactBatch,
                                user_id: key,
                                session_id: session.sessionId,
                            }, `contacts sync (${c + 1}-${c + contactBatch.length}/${cleanContacts.length})`, 15000, key);
                        } catch (cErr) {
                            console.error(`[${session.sessionId}] Failed forwarding contacts chunk:`, cErr?.message || cErr);
                        }
                    }
                }

                const CHUNK_SIZE = 50;
                if (extractedMessages.length === 0) {
                    await forwardToLaravel({
                        event: 'history_sync',
                        chats: cleanChats,
                        contacts: [],
                        messages: [],
                        data: [],
                        chunk_index: 0,
                        total_chunks: 1,
                        is_latest: Boolean(isLatest),
                        sync_type: syncType,
                    }, `history_sync (${cleanChats.length} chats, 0 messages)`, 30000, key);
                } else {
                    const totalChunks = Math.ceil(extractedMessages.length / CHUNK_SIZE);
                    console.log(
                        `[${session.sessionId}] History sync: dispatching ${extractedMessages.length} messages in ${totalChunks} sequential chunks of ${CHUNK_SIZE}...`
                    );

                    for (let i = 0; i < totalChunks; i++) {
                        const chunkMessages = extractedMessages.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
                        try {
                            await forwardToLaravel({
                                event: 'history_sync',
                                chats: i === 0 ? cleanChats : [],
                                contacts: [],
                                messages: chunkMessages,
                                data: chunkMessages,
                                chunk_index: i,
                                total_chunks: totalChunks,
                                is_latest: Boolean(isLatest && i === totalChunks - 1),
                                sync_type: syncType,
                            }, `history_sync (chunk ${i + 1}/${totalChunks}, ${chunkMessages.length} msgs)`, 30000, key);
                        } catch (chunkErr) {
                            console.error(`[${session.sessionId}] Failed forwarding history_sync chunk ${i + 1}/${totalChunks}:`, chunkErr?.message || chunkErr);
                        }
                    }
                }
            } catch (historyErr) {
                console.error(`[${session.sessionId}] Error handling messaging-history.set:`, historyErr);
            }
        });

            } finally {
                session.initPromise = null;
            }
        })();

        await session.initPromise;

        if (options.waitForQrMs > 0) {
            await this.waitForQrOrOpen(session, options.waitForQrMs);
        }

        return session;
    }

    formatSessionStatus(userId) {
        const key = this.normalizeKey(userId);
        let session = this.sessions.get(key);
        const authFolder = this.getAuthFolder(key);
        const credsPath = path.join(authFolder, 'creds.json');
        const authSessionId = key === 'default' ? 'default' : `user_${key}`;

        // Creds come from the live MySQL-backed state; a legacy creds.json is only a fallback
        let diskCreds = authStore.getCachedCreds(authSessionId);
        if (!diskCreds && fs.existsSync(credsPath)) {
            try {
                diskCreds = JSON.parse(fs.readFileSync(credsPath, 'utf8'));
            } catch (_) {}
        }
        const hasSavedCreds = hasSavedSession(authSessionId, authFolder);

        if (session && session.sock) {
            const state = session.sock.authState?.state || session.sock.authState;
            const hasAuthIdentity = Boolean(
                session.sock.user?.id ||
                state?.creds?.me?.id ||
                session.sock.authState?.creds?.me?.id ||
                session.credsMe?.id ||
                diskCreds?.me?.id
            );

            // Check if socket is open and ready (1 = OPEN)
            if (
                (session.sock.ws?.readyState === 1 || isSocketOpen(session.sock)) &&
                (session.status === 'connected' || (hasAuthIdentity && !session.qr && session.status !== 'qr_ready'))
            ) {
                session.status = 'connected';
                session.qr = null;
            }
        }

        // If this user's own session is not yet connected (and not showing a QR), check if another active session
        // in memory is already open for the same WhatsApp account
        if ((!session || (session.status !== 'connected' && session.status !== 'qr_ready')) && !session?.qr) {
            const diskPhone = diskCreds?.me?.id
                ? `+${String(diskCreds.me.id).split('@')[0].split(':')[0].replace(/\D/g, '')}`
                : null;

            if (diskPhone) {
                for (const candidate of this.sessions.values()) {
                    if (candidate && candidate.sock && (candidate.sock.ws?.readyState === 1 || isSocketOpen(candidate.sock))) {
                        const candAccount = getAccountInfo(candidate.sock, { me: candidate.credsMe });
                        if (candAccount.phone && candAccount.phone === diskPhone) {
                            session = candidate;
                            session.status = 'connected';
                            break;
                        }
                    }
                }
            }
        }

        if (!session) {
            return {
                success: true,
                user_id: key === 'default' ? null : (Number(key) || key),
                session_id: key === 'default' ? 'default' : `user_${key}`,
                status: 'disconnected',
                connected: false,
                phone: null,
                whatsapp_number: null,
                qr: null,
                has_qr: false,
                uptime_seconds: Math.floor(process.uptime()),
                uptime_human: formatUptime(process.uptime()),
                memory: getMemoryMetrics(),
                account: { phone: null, name: null, jid: null },
                last_disconnect: null,
                has_saved_creds: hasSavedCreds,
            };
        }

        let state = session.status;
        const account = getAccountInfo(session.sock, diskCreds || { me: session.credsMe });

        if (state === 'connected' && (!session.sock || (!account.phone && !account.jid))) {
            state = 'connecting';
        }

        return {
            success: true,
            user_id: key === 'default' ? null : (Number(key) || key),
            session_id: key === 'default' ? 'default' : `user_${key}`,
            status: state, // 'connected' | 'qr_ready' | 'connecting' | 'disconnected'
            connected: state === 'connected',
            phone: state === 'connected' ? account.phone : null,
            whatsapp_number: state === 'connected' ? account.phone : null,
            qr: state === 'connected' ? null : session.qr,
            has_qr: Boolean(session.qr && state !== 'connected'),
            uptime_seconds: Math.floor(process.uptime()),
            uptime_human: formatUptime(process.uptime()),
            memory: getMemoryMetrics(),
            account,
            last_disconnect: state === 'connected' ? null : session.lastDisconnect,
        };
    }

    async logoutSession(userId, autoReconnect = false) {
        const key = this.normalizeKey(userId);
        const session = this.sessions.get(key);
        const authFolder = this.getAuthFolder(key);

        if (session) {
            session.isRestarting = true;
            session.status = 'disconnected';
            session.qr = null;

            if (session.sock) {
                try {
                    await session.sock.logout();
                } catch (err) {
                    console.warn(`[${session.sessionId}] Socket logout error (continuing cleanup):`, err.message);
                }
                try {
                    session.sock.end(new Error('Manual GUI logout'));
                } catch (_) {}
                session.sock = null;
            }
            session.isRestarting = false;
        }

        // Remove the auth state from MySQL (and any legacy on-disk copy so it is not re-imported on next boot)
        try {
            await authStore.removeSession(key === 'default' ? 'default' : `user_${key}`);
            console.log(`[user_${key}] Auth state deleted from MySQL`);
        } catch (dbErr) {
            console.warn(`[user_${key}] Error deleting auth state from MySQL:`, dbErr.message);
        }

        if (fs.existsSync(authFolder)) {
            try {
                fs.rmSync(authFolder, { recursive: true, force: true });
                console.log(`[user_${key}] Legacy auth directory deleted: ${authFolder}`);
            } catch (fsErr) {
                console.warn(`[user_${key}] Error deleting auth directory:`, fsErr.message);
            }
        }

        this.sessions.delete(key);

        if (autoReconnect) {
            setTimeout(() => {
                this.initSession(key).catch(err =>
                    console.error(`[user_${key}] Failed to re-init after logout:`, err.message)
                );
            }, 800);
        }
    }

    async restartSession(userId) {
        const key = this.normalizeKey(userId);
        const session = this.sessions.get(key);

        if (session) {
            session.isRestarting = true;
            session.status = 'connecting';
            session.qr = null;

            if (session.sock) {
                try {
                    session.sock.end(undefined);
                } catch (err) {
                    console.warn(`[${session.sessionId}] Socket end error on restart:`, err.message);
                }
                session.sock = null;
            }
        }

        setTimeout(async () => {
            try {
                if (session) session.isRestarting = false;
                await this.initSession(key);
                console.log(`[user_${key}] WhatsApp session re-initialized after soft restart.`);
            } catch (connErr) {
                if (session) session.isRestarting = false;
                console.error(`[user_${key}] Failed to re-initialize session on restart:`, connErr.message);
            }
        }, 1200);
    }

    /**
     * On boot, restore every saved session: those stored in MySQL (`wa_auth_states`) plus any legacy
     * ./sessions/user_* folder that still has a creds.json (it is imported into MySQL by initSession).
     */
    async restoreExistingSessions() {
        try {
            const toRestore = new Set(authStore.listCredSessions());

            if (fs.existsSync(sessionsRootDir)) {
                const entries = fs.readdirSync(sessionsRootDir, { withFileTypes: true });
                for (const entry of entries) {
                    if (entry.isDirectory() && entry.name.startsWith('user_')) {
                        const credsFile = path.join(sessionsRootDir, entry.name, 'creds.json');
                        if (fs.existsSync(credsFile)) {
                            toRestore.add(entry.name);
                        }
                    }
                }
            }

            if (fs.existsSync(path.join(legacyAuthFolder, 'creds.json'))) {
                toRestore.add('default');
            }

            for (const sessionId of toRestore) {
                const userId = sessionId === 'default' ? 'default' : sessionId.replace(/^user_/, '');
                if (!userId) continue;
                console.log(`[Startup] Restoring saved WhatsApp session for ${sessionId}...`);
                this.initSession(userId).catch(err =>
                    console.error(`[Startup] Failed to restore ${sessionId}:`, err.message)
                );
            }
        } catch (err) {
            console.error('[Startup] Error restoring saved sessions:', err.message);
        }
    }
}

const sessionManager = new SessionManager();

// ============================================================================
// Multi-Session Endpoints (`/sessions/*`)
// ============================================================================

/**
 * POST /sessions/create
 * Body: { user_id: number|string }
 * Initializes Baileys for this user in `./sessions/user_${userId}` and returns the base64 QR code.
 */
app.post('/sessions/create', authenticate, async (req, res) => {
    const userId = req.body?.user_id ?? req.query?.user_id;
    if (!userId) {
        return res.status(400).json({
            success: false,
            error: 'The "user_id" field is required.',
        });
    }

    try {
        await sessionManager.initSession(userId, { waitForQrMs: 1500 });
        const statusPayload = sessionManager.formatSessionStatus(userId);
        return res.status(200).json(statusPayload);
    } catch (error) {
        console.error(`Error creating session for user ${userId}:`, error);
        return res.status(500).json({
            success: false,
            error: error.message || 'Failed to initialize WhatsApp session.',
        });
    }
});

/**
 * GET /sessions/status/:user_id
 * Checks if the socket for `user_id` is 'connected', 'qr_ready' ('qr'), 'connecting', or 'disconnected'.
 */
app.get('/sessions/status/:user_id', authenticate, async (req, res) => {
    const userId = req.params.user_id;
    const autoInit = req.query.auto_init === '1' || req.query.auto_init === 'true';

    const session = sessionManager.getSession(userId);
    const authFolder = sessionManager.getAuthFolder(sessionManager.normalizeKey(userId));
    const hasSavedCreds = hasSavedSession(
        authFolder === legacyAuthFolder ? 'default' : path.basename(authFolder),
        authFolder
    );

    if (session && session.sock) {
        const state = session.sock.authState?.state || session.sock.authState;
        const hasIdentity = Boolean(
            session.sock.user?.id ||
            state?.creds?.me?.id ||
            session.sock.authState?.creds?.me?.id ||
            session.credsMe?.id ||
            hasSavedCreds
        );

        // Check if socket is open and ready (1 = OPEN)
        if ((session.sock.ws?.readyState === 1 || isSocketOpen(session.sock)) && (session.status === 'connected' || (hasIdentity && !session.qr))) {
            session.status = 'connected';
            session.qr = null;
            const statusPayload = sessionManager.formatSessionStatus(userId);
            return res.status(200).json({
                ...statusPayload,
                status: 'connected',
                connected: true,
            });
        }
    }

    if (!session && (hasSavedCreds || autoInit)) {
        sessionManager.initSession(userId, { waitForQrMs: 0 }).catch(err => {
            console.warn(`Background init on status check for user ${userId} failed:`, err.message);
        });
    }

    return res.status(200).json(sessionManager.formatSessionStatus(userId));
});

/**
 * POST /sessions/logout
 * Body: { user_id: number|string, reconnect?: boolean }
 * Logs out the user and deletes their specific `./sessions/user_${userId}` folder.
 */
app.post('/sessions/logout', authenticate, async (req, res) => {
    const userId = req.body?.user_id ?? req.query?.user_id;
    if (!userId) {
        return res.status(400).json({
            success: false,
            error: 'The "user_id" field is required.',
        });
    }

    try {
        const reconnect = Boolean(req.body?.reconnect);
        await sessionManager.logoutSession(userId, reconnect);
        return res.status(200).json({
            success: true,
            user_id: Number(userId) || userId,
            session_id: `user_${userId}`,
            message: 'WhatsApp session logged out and credentials cleared.',
            status: 'disconnected',
        });
    } catch (error) {
        console.error(`Error logging out session for user ${userId}:`, error);
        return res.status(500).json({
            success: false,
            error: error.message || 'Failed to logout session.',
        });
    }
});

/**
 * POST /sessions/restart
 * Body: { user_id: number|string }
 * Soft-restarts the user's Baileys socket without deleting `./sessions/user_${userId}`.
 */
app.post('/sessions/restart', authenticate, async (req, res) => {
    const userId = req.body?.user_id ?? req.query?.user_id;
    if (!userId) {
        return res.status(400).json({
            success: false,
            error: 'The "user_id" field is required.',
        });
    }

    try {
        await sessionManager.restartSession(userId);
        return res.status(200).json({
            success: true,
            user_id: Number(userId) || userId,
            session_id: `user_${userId}`,
            message: 'WhatsApp user session restarting...',
            status: 'connecting',
        });
    } catch (error) {
        console.error(`Error restarting session for user ${userId}:`, error);
        return res.status(500).json({
            success: false,
            error: error.message || 'Failed to restart session.',
        });
    }
});

/**
 * POST /sessions/:userId/sync-contacts or /sessions/sync-contacts
 * Body: { user_id?: number|string }
 * Re-pushes cached phonebook contacts for this session to Laravel CRM on demand.
 */
app.post(['/sessions/:userId/sync-contacts', '/sessions/sync-contacts', '/api/sync-contacts'], authenticate, async (req, res) => {
    const rawUserId = req.params.userId || req.body?.user_id || req.query?.user_id || 'default';
    const key = sessionManager.normalizeKey(rawUserId);
    const session = sessionManager.getSession(key);

    const cachedMap = sessionManager.loadCachedContacts(key);
    const allContacts = Object.values(cachedMap);

    const validContacts = allContacts.filter(c => {
        const jid = c?.id || c?.jid;
        if (!jid || isJidIgnored(jid) || jid.endsWith('@g.us')) return false;
        return Boolean(c.name || c.notify);
    });

    if (validContacts.length === 0) {
        return res.status(200).json({
            success: false,
            count: 0,
            message: 'No cached contacts found for this session. Please re-link WhatsApp or wait for WhatsApp to sync contacts.',
        });
    }

    const sessionId = session?.sessionId || `user_${key}`;
    const CHUNK_SIZE = 100;
    let forwardedCount = 0;

    for (let c = 0; c < validContacts.length; c += CHUNK_SIZE) {
        const batch = validContacts.slice(c, c + CHUNK_SIZE);
        try {
            await forwardToLaravel({
                event: 'contacts.upsert',
                contacts: batch,
                user_id: key,
                session_id: sessionId,
            }, `manual contacts sync (${c + 1}-${c + batch.length}/${validContacts.length})`, 15000, key);
            forwardedCount += batch.length;
        } catch (err) {
            console.error(`[user_${key}] Failed re-syncing contacts chunk:`, err?.message || err);
        }
    }

    return res.status(200).json({
        success: true,
        count: forwardedCount,
        total: validContacts.length,
        message: `Successfully re-synced ${forwardedCount} contacts to CRM.`,
    });
});

// ============================================================================
// Management & Messaging API Endpoints (User-scoped when `user_id` is passed)
// ============================================================================

app.get('/api/status', authenticate, async (req, res) => {
    const userId = req.query.user_id || 'default';
    return res.status(200).json(sessionManager.formatSessionStatus(userId));
});

app.get('/api/qr', authenticate, async (req, res) => {
    const userId = req.query.user_id || 'default';
    const info = sessionManager.formatSessionStatus(userId);
    return res.status(200).json({
        success: true,
        user_id: info.user_id,
        status: info.status,
        qr: info.qr,
    });
});

app.post('/api/logout', authenticate, async (req, res) => {
    const userId = req.body?.user_id ?? req.query?.user_id ?? 'default';
    try {
        await sessionManager.logoutSession(userId, true);
        return res.status(200).json({
            success: true,
            message: 'WhatsApp session logged out. Generating new QR code.',
            status: 'disconnected',
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            error: error.message || 'Failed to logout.',
        });
    }
});

app.post('/api/restart', authenticate, async (req, res) => {
    const userId = req.body?.user_id ?? req.query?.user_id ?? 'default';
    try {
        await sessionManager.restartSession(userId);
        return res.status(200).json({
            success: true,
            message: 'WhatsApp gateway engine restarting. Reconnecting socket...',
            status: 'connecting',
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            error: error.message || 'Failed to restart engine.',
        });
    }
});

app.get('/resolve-lid/:lid', authenticate, async (req, res) => {
    const rawLid = String(req.params.lid || '').trim();
    const jid = rawLid.includes('@') ? rawLid : `${rawLid}@lid`;
    const activeSession = sessionManager.resolveActiveSession(req.query.user_id);
    const phone = await resolvePhoneFromJid(jid, null, activeSession?.sock, activeSession?.authFolder);

    return res.status(200).json({
        lid: jid,
        phone,
    });
});

app.post(['/contacts/profile-picture', '/api/avatar'], authenticate, async (req, res) => {
    const { user_id, jid, phone } = req.body;
    const activeSession = sessionManager.resolveActiveSession(user_id);
    const sock = activeSession?.sock;

    if (!sock) {
        return res.status(503).json({
            success: false,
            error: 'No active WhatsApp session connected.',
        });
    }

    try {
        const rawTarget = jid || (phone ? `${String(phone).replace(/\D/g, '')}@s.whatsapp.net` : null);
        if (!rawTarget) {
            return res.status(400).json({
                success: false,
                error: 'Missing jid or phone in request body.',
            });
        }

        const avatarUrl = await fetchProfilePicture(sock, rawTarget, phone);
        return res.status(200).json({
            success: true,
            jid: rawTarget,
            phone: phone || null,
            avatar_url: avatarUrl,
            avatarUrl: avatarUrl,
        });
    } catch (err) {
        return res.status(500).json({
            success: false,
            error: err.message || 'Failed to fetch profile picture.',
        });
    }
});

// POST /fetch-history endpoint to request on-demand chat history from WhatsApp
app.post(['/fetch-history', '/api/fetch-history'], authenticate, async (req, res) => {
    const {
        user_id,
        jid,
        phone,
        count = 50,
        oldest_message_key,
        oldest_message_timestamp,
    } = req.body;

    const activeSession = sessionManager.resolveActiveSession(user_id);
    const sock = activeSession?.sock;

    if (!sock) {
        return res.status(503).json({
            success: false,
            error: 'No active WhatsApp session connected.',
        });
    }

    try {
        let rawTarget = jid;
        if (!rawTarget && phone) {
            const cleanPhone = String(phone).replace(/\D/g, '');
            rawTarget = String(phone).includes('@') ? String(phone) : `${cleanPhone}@s.whatsapp.net`;
        }

        if (!rawTarget) {
            return res.status(400).json({
                success: false,
                error: 'Missing jid or phone in request body.',
            });
        }

        // WhatsApp Multi-Device history sync capability check
        if (typeof sock.fetchMessageHistory !== 'function') {
            return res.status(501).json({
                success: false,
                error: 'fetchMessageHistory is not supported or exposed by this Baileys socket instance.',
                limitation: 'WhatsApp Multi-Device history synchronization is client-pushed by the WhatsApp primary mobile device upon pairing and cannot be queried on-demand without socket PDO support.',
            });
        }

        const msgCount = Math.max(1, Math.min(parseInt(count, 10) || 50, 100));

        // Format anchor key for WhatsApp PeerDataOperation
        const anchorKey = oldest_message_key || {
            remoteJid: rawTarget,
            fromMe: false,
            id: 'ANCHOR_' + Date.now(),
        };

        const anchorTimestamp = oldest_message_timestamp
            ? (oldest_message_timestamp > 1e11 ? Math.floor(oldest_message_timestamp) : Math.floor(oldest_message_timestamp * 1000))
            : Date.now();

        console.log(`[${activeSession.sessionId}] Requesting on-demand history for ${rawTarget} (count: ${msgCount}, anchor: ${anchorKey.id})...`);

        // Send Peer Data Operation (HISTORY_SYNC_ON_DEMAND) to WhatsApp primary phone
        await sock.fetchMessageHistory(msgCount, anchorKey, anchorTimestamp);

        return res.status(200).json({
            success: true,
            session_id: activeSession.sessionId,
            jid: rawTarget,
            count: msgCount,
            method: 'fetchMessageHistory (PDO: HISTORY_SYNC_ON_DEMAND)',
            message: 'On-demand history request dispatched to the primary WhatsApp device. If the phone is online and acknowledges the request, WhatsApp will stream historical messages asynchronously via messaging-history.set.',
            note: 'WhatsApp Multi-Device is client-pushed. If the phone was asleep, offline, or has no record of the anchor message, WhatsApp may not send back history.',
        });
    } catch (err) {
        console.error(`[${activeSession?.sessionId || 'unknown'}] Error in /fetch-history:`, err);
        return res.status(500).json({
            success: false,
            error: err.message || 'Failed to dispatch fetchMessageHistory request.',
        });
    }
});

// POST /send, /api/send, and /sessions/send endpoint to send WhatsApp messages (text or media)
app.post(['/send', '/api/send', '/sessions/send'], authenticate, async (req, res) => {
    const {
        user_id,
        phone,
        message,
        media_url,
        media_base64,
        media_type,
        mimetype,
        file_name,
        is_voice_note,
        quoted_message_key,
        contact,
        contacts,
    } = req.body;

    const mediaType = String(media_type || '').toLowerCase();
    const isContactSend = mediaType === 'contact' || Boolean(contact) || (Array.isArray(contacts) && contacts.length > 0);
    const hasMedia = Boolean(media_url || media_base64);

    if (!phone || (!hasMedia && !isContactSend && !message)) {
        return res.status(400).json({
            success: false,
            error: (hasMedia || isContactSend)
                ? 'The "phone" field is required.'
                : 'Both "phone" and "message" fields are required (or provide media_url / media_base64 / contacts).',
        });
    }

    if (hasMedia && !MEDIA_TYPES.includes(mediaType)) {
        return res.status(400).json({
            success: false,
            error: `"media_type" must be one of: ${MEDIA_TYPES.join(', ')}.`,
        });
    }

    if (media_url && !/^https?:\/\//i.test(String(media_url))) {
        return res.status(400).json({
            success: false,
            error: '"media_url" must be an http(s) URL.',
        });
    }

    const activeSession = sessionManager.resolveActiveSession(user_id);
    const sock = activeSession?.sock;

    if (!sock) {
        return res.status(503).json({
            success: false,
            code: 'AGENT_WHATSAPP_DISCONNECTED',
            user_id: user_id ?? null,
            error: user_id
                ? `WhatsApp session for user ${user_id} is not connected.`
                : 'No connected WhatsApp session is available.',
        });
    }

    try {
        const rawPhone = String(phone).trim();
        let jid = rawPhone.includes('@')
            ? rawPhone
            : `${rawPhone.replace(/\D/g, '')}@s.whatsapp.net`;

        // Verify that the recipient number is registered on WhatsApp before attempting to send (with 2.5s timeout so it never hangs)
        const digits = rawPhone.replace(/\D/g, '');
        const formattedNumber = rawPhone.includes('@') ? rawPhone : (digits ? `${digits}@s.whatsapp.net` : rawPhone);

        if (!rawPhone.endsWith('@g.us') && !rawPhone.endsWith('@broadcast') && !rawPhone.endsWith('@newsletter')) {
            try {
                const checkRes = await withTimeout(sock.onWhatsApp(formattedNumber), 2500);
                const result = Array.isArray(checkRes) ? checkRes[0] : null;
                if (!result || !result.exists) {
                    console.warn(`[${activeSession.sessionId}][onWhatsApp] Number ${formattedNumber} is NOT registered on WhatsApp. Rejecting send.`);
                    return res.status(422).json({
                        success: false,
                        error: 'NOT_ON_WHATSAPP',
                        message: 'هذا الرقم غير مسجل على واتساب.',
                        phone: rawPhone,
                        jid: formattedNumber,
                    });
                }
                if (result.jid) {
                    jid = result.jid;
                }
            } catch (onWaErr) {
                if (onWaErr.message === 'timeout') {
                    console.warn(`[${activeSession.sessionId}][onWhatsApp] Timed out after 2.5s for ${formattedNumber}; proceeding with sendMessage.`);
                } else {
                    console.error(`[${activeSession.sessionId}][onWhatsApp] Verification check failed for ${formattedNumber}:`, onWaErr.message);
                    return res.status(422).json({
                        success: false,
                        error: 'NOT_ON_WHATSAPP',
                        message: 'Could not verify WhatsApp registration: ' + onWaErr.message,
                        phone: rawPhone,
                        jid: formattedNumber,
                    });
                }
            }
        }

        // Configure quoted message option if replying
        const sendOptions = {};
        if (quoted_message_key && quoted_message_key.id) {
            sendOptions.quoted = {
                key: {
                    id: String(quoted_message_key.id),
                    remoteJid: quoted_message_key.remoteJid
                        ? (String(quoted_message_key.remoteJid).includes('@')
                            ? String(quoted_message_key.remoteJid)
                            : `${rawPhoneToDigits(String(quoted_message_key.remoteJid))}@s.whatsapp.net`)
                        : jid,
                    fromMe: Boolean(quoted_message_key.fromMe),
                    participant: quoted_message_key.participant,
                },
                message: {
                    conversation: String(quoted_message_key.text || quoted_message_key.body || ''),
                },
            };
        }

        let result = null;

        if (isContactSend) {
            const rawContactList = Array.isArray(contacts) && contacts.length > 0
                ? contacts
                : (contact ? [contact] : []);

            if (rawContactList.length === 0 && message) {
                try {
                    const parsedBody = JSON.parse(String(message));
                    if (Array.isArray(parsedBody?.contacts)) {
                        rawContactList.push(...parsedBody.contacts);
                    } else if (parsedBody?.name || parsedBody?.phone) {
                        rawContactList.push(parsedBody);
                    }
                } catch (_) {}
            }

            const vcardItems = rawContactList
                .map(c => ({
                    displayName: String(c?.name || c?.displayName || 'Contact').trim() || 'Contact',
                    vcard: buildVcardString(c),
                }))
                .filter(c => c.vcard);

            if (vcardItems.length === 0) {
                return res.status(400).json({
                    success: false,
                    error: 'At least one valid contact (name and phone) is required for contact send.',
                });
            }

            result = await sock.sendMessage(jid, {
                contacts: {
                    displayName: vcardItems[0].displayName,
                    contacts: vcardItems,
                },
            }, sendOptions);
        } else if (hasMedia) {
            const voiceNote = mediaType === 'audio' && (
                is_voice_note === true ||
                is_voice_note === 'true' ||
                is_voice_note === 1 ||
                is_voice_note === '1'
            );

            let source;
            let finalMimetype = mimetype || defaultMimetype(mediaType, voiceNote);

            if (voiceNote) {
                console.log(`[${activeSession.sessionId}] Converting outgoing voice note to OPUS-encoded OGG for ${jid}...`);
                const rawInput = media_url
                    ? String(media_url)
                    : Buffer.from(String(media_base64), 'base64');

                const opusBuffer = await convertToOpusVoiceNote(rawInput);
                source = opusBuffer;
                finalMimetype = 'audio/ogg; codecs=opus';
            } else {
                source = media_url
                    ? { url: String(media_url) }
                    : Buffer.from(String(media_base64), 'base64');
            }

            const content = { [mediaType]: source };

            if (mediaType === 'sticker') {
                content.mimetype = 'image/webp';
            } else if (mediaType === 'audio') {
                content.ptt = voiceNote;
                content.mimetype = finalMimetype;
            } else {
                if (message) {
                    content.caption = String(message);
                }
                content.mimetype = finalMimetype;
            }

            if (mediaType === 'document') {
                content.fileName = file_name || 'file';
            }

            result = await sock.sendMessage(jid, content, sendOptions);

            if ((mediaType === 'audio' || mediaType === 'sticker') && message) {
                await sock.sendMessage(jid, { text: String(message) });
            }
        } else {
            try {
                result = await withTimeout(sock.sendMessage(jid, { text: String(message) }, sendOptions), 3500);
            } catch (sendErr) {
                if (sendErr.message === 'timeout') {
                    console.warn(`[${activeSession.sessionId}] sock.sendMessage ACK took >3.5s for ${jid}; returning immediate success.`);
                    result = { key: { id: `BAILEYS_${Date.now()}`, remoteJid: jid, fromMe: true } };
                } else {
                    throw sendErr;
                }
            }
        }

        if (activeSession) {
            activeSession.status = 'connected';
            activeSession.qr = null;
            activeSession.lastDisconnect = null;
        }

        const messageId = result?.key?.id || `BAILEYS_${Date.now()}`;

        return res.status(200).json({
            success: true,
            user_id: activeSession.userId === 'default' ? null : (Number(activeSession.userId) || activeSession.userId),
            session_id: activeSession.sessionId,
            id: messageId,
            jid,
            media_type: hasMedia ? mediaType : null,
            result: {
                key: {
                    id: messageId,
                    remoteJid: result?.key?.remoteJid || jid,
                    fromMe: true,
                },
                messageTimestamp: toEpochSeconds(result?.messageTimestamp),
            },
        });
    } catch (error) {
        console.error('Error sending message:', error);
        return res.status(500).json({
            success: false,
            error: error.message || 'Failed to send WhatsApp message.',
        });
    }
});

// POST /react endpoint
app.post('/react', authenticate, async (req, res) => {
    const { user_id, jid, message_key, emoji } = req.body;
    const activeSession = sessionManager.resolveActiveSession(user_id);
    const sock = activeSession?.sock;

    if (!sock) {
        return res.status(503).json({
            success: false,
            error: 'WhatsApp socket is not initialized yet.',
        });
    }

    const rawJid = jid ? String(jid).trim() : '';
    const targetJid = rawJid
        ? (rawJid.includes('@') ? rawJid : `${rawPhoneToDigits(rawJid)}@s.whatsapp.net`)
        : '';

    const messageId = typeof message_key === 'string' ? message_key : message_key?.id;

    if (!targetJid || !messageId) {
        return res.status(400).json({
            success: false,
            error: 'Both "jid" and "message_key" (with id) are required.',
        });
    }

    try {
        const key = {
            id: messageId,
            remoteJid: (typeof message_key === 'object' && message_key?.remoteJid)
                ? (String(message_key.remoteJid).includes('@')
                    ? String(message_key.remoteJid)
                    : `${rawPhoneToDigits(String(message_key.remoteJid))}@s.whatsapp.net`)
                : targetJid,
            fromMe: typeof message_key === 'object' ? Boolean(message_key.fromMe) : false,
            participant: typeof message_key === 'object' ? message_key.participant : undefined,
        };

        const reactionEmoji = String(emoji ?? '').trim();

        const result = await sock.sendMessage(targetJid, {
            react: {
                text: reactionEmoji,
                key,
            },
        });

        return res.status(200).json({
            success: true,
            id: result?.key?.id || null,
            result,
        });
    } catch (error) {
        console.error('Error reacting to message:', error);
        return res.status(500).json({
            success: false,
            error: error.message || 'Failed to react to message.',
        });
    }
});

// POST /edit endpoint
app.post('/edit', authenticate, async (req, res) => {
    const { user_id, jid, message_key, new_text } = req.body;
    const activeSession = sessionManager.resolveActiveSession(user_id);
    const sock = activeSession?.sock;

    if (!sock) {
        return res.status(503).json({
            success: false,
            error: 'WhatsApp socket is not initialized yet.',
        });
    }

    const rawJid = jid ? String(jid).trim() : '';
    const targetJid = rawJid
        ? (rawJid.includes('@') ? rawJid : `${rawPhoneToDigits(rawJid)}@s.whatsapp.net`)
        : '';

    const messageId = typeof message_key === 'string' ? message_key : message_key?.id;
    const text = typeof new_text === 'string' ? new_text : '';

    if (!targetJid || !messageId) {
        return res.status(400).json({
            success: false,
            error: 'Both "jid" and "message_key" (with id) are required.',
        });
    }

    try {
        const key = {
            id: messageId,
            remoteJid: (typeof message_key === 'object' && message_key?.remoteJid)
                ? (String(message_key.remoteJid).includes('@')
                    ? String(message_key.remoteJid)
                    : `${rawPhoneToDigits(String(message_key.remoteJid))}@s.whatsapp.net`)
                : targetJid,
            fromMe: typeof message_key === 'object' && message_key?.fromMe !== undefined
                ? Boolean(message_key.fromMe)
                : true,
            participant: typeof message_key === 'object' ? message_key.participant : undefined,
        };

        const result = await sock.sendMessage(targetJid, {
            text,
            edit: key,
        });

        return res.status(200).json({
            success: true,
            id: result?.key?.id || messageId,
            result,
        });
    } catch (error) {
        console.error('Error editing message:', error);
        return res.status(500).json({
            success: false,
            error: error.message || 'Failed to edit message.',
        });
    }
});

// POST /delete endpoint
app.post('/delete', authenticate, async (req, res) => {
    const { user_id, jid, message_key } = req.body;
    const activeSession = sessionManager.resolveActiveSession(user_id);
    const sock = activeSession?.sock;

    if (!sock) {
        return res.status(503).json({
            success: false,
            error: 'WhatsApp socket is not initialized yet.',
        });
    }

    const rawJid = jid ? String(jid).trim() : '';
    const targetJid = rawJid
        ? (rawJid.includes('@') ? rawJid : `${rawPhoneToDigits(rawJid)}@s.whatsapp.net`)
        : '';

    const messageId = typeof message_key === 'string' ? message_key : message_key?.id;

    if (!targetJid || !messageId) {
        return res.status(400).json({
            success: false,
            error: 'Both "jid" and "message_key" (with id) are required.',
        });
    }

    try {
        const key = {
            id: messageId,
            remoteJid: (typeof message_key === 'object' && message_key?.remoteJid)
                ? (String(message_key.remoteJid).includes('@')
                    ? String(message_key.remoteJid)
                    : `${rawPhoneToDigits(String(message_key.remoteJid))}@s.whatsapp.net`)
                : targetJid,
            fromMe: typeof message_key === 'object' && message_key?.fromMe !== undefined
                ? Boolean(message_key.fromMe)
                : true,
            participant: typeof message_key === 'object' ? message_key.participant : undefined,
        };

        const result = await sock.sendMessage(targetJid, {
            delete: key,
        });

        return res.status(200).json({
            success: true,
            id: result?.key?.id || messageId,
            result,
        });
    } catch (error) {
        console.error('Error revoking message:', error);
        return res.status(500).json({
            success: false,
            error: error.message || 'Failed to revoke message.',
        });
    }
});

// POST /read endpoint
app.post('/read', authenticate, async (req, res) => {
    const { user_id, jid, keys } = req.body;
    const activeSession = sessionManager.resolveActiveSession(user_id);
    const sock = activeSession?.sock;

    if (!sock) {
        return res.status(503).json({
            success: false,
            error: 'WhatsApp socket is not initialized yet.',
        });
    }

    const rawJid = jid ? String(jid).trim() : '';
    const formattedJid = rawJid
        ? (rawJid.includes('@') ? rawJid : `${rawPhoneToDigits(rawJid)}@s.whatsapp.net`)
        : '';

    const rawKeys = Array.isArray(keys) ? keys : (keys ? [keys] : []);

    if (!formattedJid && rawKeys.length === 0) {
        return res.status(400).json({
            success: false,
            error: 'Either "jid" or message "keys" must be provided.',
        });
    }

    try {
        const formattedKeys = rawKeys.map(k => {
            if (typeof k === 'string') {
                return {
                    remoteJid: formattedJid,
                    id: k,
                    fromMe: false,
                };
            }
            const keyJid = k.remoteJid
                ? (String(k.remoteJid).includes('@') ? String(k.remoteJid) : `${rawPhoneToDigits(String(k.remoteJid))}@s.whatsapp.net`)
                : formattedJid;

            return {
                remoteJid: keyJid,
                id: k.id || k.key?.id,
                participant: k.participant,
                fromMe: false,
            };
        }).filter(k => k.id && k.remoteJid);

        if (formattedKeys.length > 0) {
            await sock.readMessages(formattedKeys);
        }

        return res.status(200).json({
            success: true,
            marked_read: formattedKeys.length,
        });
    } catch (error) {
        console.error('Error marking messages as read:', error);
        return res.status(500).json({
            success: false,
            error: error.message || 'Failed to send read receipts.',
        });
    }
});

function rawPhoneToDigits(phone) {
    return String(phone || '').replace(/\D/g, '');
}

// Connect to MySQL (auth state store) before accepting traffic / restoring sessions
authStore.init()
    .then((savedSessions) => {
        console.log(`[AuthState] MySQL auth store ready (${savedSessions.length} saved session(s)).`);
        app.listen(PORT, () => {
            console.log(`WhatsApp Multi-Session gateway service running on http://localhost:${PORT}`);
            sessionManager.restoreExistingSessions();
        });
    })
    .catch((err) => {
        console.error(`[AuthState] FATAL: cannot use the MySQL auth store: ${err.message}`);
        process.exit(1);
    });
