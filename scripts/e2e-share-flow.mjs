#!/usr/bin/env node
/**
 * E2E: same crypto path as iClaw share.js → POST /api/shares → GET blob →
 * decrypt + gunzip like viewer.js; then GET /s/:id and assert viewer HTML.
 *
 * Usage (from repo root, iClaw-cloud running):
 *   node scripts/e2e-share-flow.mjs
 *   CLOUD_URL=http://127.0.0.1:4000 node scripts/e2e-share-flow.mjs
 */
import { randomBytes } from 'node:crypto';

const CLOUD = (process.env.CLOUD_URL || 'http://localhost:4000').replace(/\/+$/, '');

/** Same as iClaw `share.js` gzip(). */
async function gzipWeb(bytes) {
  const cs = new CompressionStream('gzip');
  const stream = new Response(new Blob([bytes]).stream().pipeThrough(cs));
  return new Uint8Array(await stream.arrayBuffer());
}

/** Same as `viewer.js` gunzip(). */
async function gunzipWeb(bytes) {
  const ds = new DecompressionStream('gzip');
  const stream = new Response(new Blob([bytes]).stream().pipeThrough(ds));
  return new Uint8Array(await stream.arrayBuffer());
}

function b64(u8) {
  return Buffer.from(u8).toString('base64');
}

function fromB64(s) {
  return Uint8Array.from(Buffer.from(s, 'base64'));
}

async function main() {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('Web Crypto (crypto.subtle) is required — use Node 20+');
  }

  const payload = {
    version: 1,
    title: 'E2E test chat',
    agent: 'openclaw/default',
    sharedAt: new Date().toISOString(),
    messages: [{ role: 'user', content: 'hello share' }],
  };
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const gz = await gzipWeb(plaintext);

  const realKeyBytes = randomBytes(32);
  const nonce = randomBytes(12);
  const key = await subtle.importKey(
    'raw',
    realKeyBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
  const ctBuf = await subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, gz);
  const ciphertext = new Uint8Array(ctBuf);

  const body = {
    ciphertext: b64(ciphertext),
    nonce: b64(nonce),
    salt: null,
    wrappedKey: null,
    hasPassword: false,
    ttlDays: 7,
    maxViews: null,
  };

  const postRes = await fetch(`${CLOUD}/api/shares`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Origin: 'http://localhost:3000',
    },
    body: JSON.stringify(body),
  });
  if (!postRes.ok) {
    const t = await postRes.text();
    throw new Error(`POST /api/shares failed ${postRes.status}: ${t}`);
  }
  const created = await postRes.json();
  if (!created.id || !created.url || !created.expiresAt) {
    throw new Error('Unexpected POST body: ' + JSON.stringify(created));
  }
  console.log('[e2e] created share', created.id);

  const getRes = await fetch(`${CLOUD}/api/shares/${encodeURIComponent(created.id)}`, {
    headers: { Accept: 'application/json' },
  });
  if (!getRes.ok) {
    throw new Error(`GET /api/shares/:id failed ${getRes.status}`);
  }
  const blob = await getRes.json();

  const decKey = await subtle.importKey(
    'raw',
    realKeyBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
  const plainBuf = await subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(blob.nonce) },
    decKey,
    fromB64(blob.ciphertext),
  );
  const gunzipped = await gunzipWeb(new Uint8Array(plainBuf));
  const out = JSON.parse(new TextDecoder().decode(gunzipped));

  if (out.title !== payload.title) {
    throw new Error(`title mismatch: ${out.title}`);
  }
  if (!out.messages?.[0] || out.messages[0].content !== 'hello share') {
    throw new Error('messages mismatch: ' + JSON.stringify(out.messages));
  }
  console.log('[e2e] decrypt round-trip OK');

  const pageRes = await fetch(`${CLOUD}/s/${created.id}`);
  if (!pageRes.ok) {
    throw new Error(`GET /s/:id failed ${pageRes.status}`);
  }
  const html = await pageRes.text();
  if (!html.includes('viewer.js') || !html.includes('share-title')) {
    throw new Error('viewer.html missing expected markers');
  }
  console.log('[e2e] viewer page OK');

  console.log('[e2e] ALL PASSED');
}

main().catch((e) => {
  console.error('[e2e] FAILED:', e.message || e);
  process.exit(1);
});
