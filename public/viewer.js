/**
 * Viewer page logic.
 *
 * Flow:
 *   1. Parse share id from /s/<id>/ and the optional key from URL fragment (#k=...).
 *   2. Fetch ciphertext metadata from /api/shares/<id>.
 *   3. If the share is password-protected, prompt for password, derive the
 *      unwrap-key via PBKDF2(SHA-256, 200 000 iter), unwrap the real key,
 *      then decrypt. Otherwise the fragment key is the real key.
 *   4. gunzip the plaintext, parse JSON, render as a minimal chat transcript.
 *
 * Everything happens in the browser — the server only ever sees opaque bytes.
 */

(() => {
  'use strict';

  const idMatch = location.pathname.match(/^\/s\/([A-Za-z0-9_-]{6,32})\/?$/);
  if (!idMatch) {
    showError('Invalid share URL.');
    return;
  }
  const shareId = idMatch[1];

  /** @type {string | null} */
  const fragmentKeyB64 = readFragmentKey();

  const $ = (sel) => /** @type {HTMLElement} */ (document.querySelector(sel));
  const meta = $('#meta');
  const loading = $('#loading');
  const gate = $('#gate');
  const errorSection = $('#error');
  const errorDetail = $('#error-detail');
  const gateError = $('#gate-error');
  const content = $('#content');
  const shareTitle = $('#share-title');
  const shareSub = $('#share-sub');
  const transcript = $('#transcript');
  const pwForm = /** @type {HTMLFormElement} */ ($('#pw-form'));
  const pwInput = /** @type {HTMLInputElement} */ ($('#pw-input'));

  fetchShare().then((blob) => {
    if (!blob) return;
    if (blob.hasPassword) {
      gate.hidden = false;
      loading.hidden = true;
      pwForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const pw = pwInput.value;
        if (!pw) return;
        gateError.hidden = true;
        gateError.textContent = '';
        try {
          await unlockWithPassword(blob, pw);
        } catch (err) {
          showGateError('Wrong password or corrupted payload.');
        }
      });
    } else {
      unlockWithFragment(blob).catch((err) => {
        console.error(err);
        showError(
          'Decryption failed. The URL may be missing the key (the part after #), ' +
            'or the share may be corrupted.',
        );
      });
    }
  });

  /* ----------------------------------------- networking ----------------- */

  async function fetchShare() {
    try {
      const res = await fetch('/api/shares/' + encodeURIComponent(shareId), {
        headers: { Accept: 'application/json' },
      });
      if (res.status === 404) {
        showError('This share has expired or never existed.');
        return null;
      }
      if (!res.ok) {
        showError('Server error: ' + res.status);
        return null;
      }
      const data = await res.json();
      renderMeta(data);
      return data;
    } catch (err) {
      console.error(err);
      showError('Network error: ' + (err && err.message ? err.message : 'unknown'));
      return null;
    }
  }

  function renderMeta(data) {
    const parts = [];
    if (data.expiresAt) {
      parts.push('expires ' + new Date(data.expiresAt).toLocaleString());
    }
    if (data.maxViews) {
      parts.push(`view ${data.viewCount}/${data.maxViews}`);
    }
    meta.textContent = parts.join(' · ');
  }

  /* ----------------------------------------- unlock paths ---------------- */

  async function unlockWithFragment(blob) {
    if (!fragmentKeyB64) {
      throw new Error('missing fragment key');
    }
    const rawKey = base64urlToBytes(fragmentKeyB64);
    const key = await importAesKey(rawKey);
    await decryptAndRender(blob, key);
  }

  async function unlockWithPassword(blob, password) {
    if (!blob.salt || !blob.wrappedKey) {
      throw new Error('password share is missing salt or wrappedKey');
    }
    const salt = base64ToBytes(blob.salt);
    const wrappedKey = base64ToBytes(blob.wrappedKey);

    // Derive the wrap-key from the password (PBKDF2-SHA256, 200k iterations).
    const baseKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey'],
    );
    const wrapKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 200_000, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    );

    // The first 12 bytes of wrappedKey are the nonce we used for wrapping;
    // the rest is ciphertext+tag.
    if (wrappedKey.length < 13) {
      throw new Error('wrappedKey too short');
    }
    const wrapNonce = wrappedKey.slice(0, 12);
    const wrapCiphertext = wrappedKey.slice(12);
    const rawKeyBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: wrapNonce },
      wrapKey,
      wrapCiphertext,
    );
    const key = await importAesKey(new Uint8Array(rawKeyBuf));
    await decryptAndRender(blob, key);
    gate.hidden = true;
  }

  async function decryptAndRender(blob, key) {
    loading.hidden = false;
    const ciphertext = base64ToBytes(blob.ciphertext);
    const nonce = base64ToBytes(blob.nonce);
    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      key,
      ciphertext,
    );

    // The payload is gzipped JSON. Use DecompressionStream (available in
    // every modern browser).
    const gunzipped = await gunzip(new Uint8Array(plainBuf));
    const text = new TextDecoder().decode(gunzipped);
    /** @type {{title?:string, agent?:string, messages?: Array<{role:string,content:string,createdAt?:string}>}} */
    const payload = JSON.parse(text);

    shareTitle.textContent = payload.title || 'Shared chat';
    const subParts = [];
    if (payload.agent) subParts.push(payload.agent);
    if (Array.isArray(payload.messages)) {
      subParts.push(`${payload.messages.length} messages`);
    }
    shareSub.textContent = subParts.join(' · ');
    renderTranscript(payload.messages || []);

    loading.hidden = true;
    content.hidden = false;
  }

  function renderTranscript(messages) {
    transcript.replaceChildren();
    for (const m of messages) {
      const wrap = document.createElement('div');
      wrap.className = 'msg msg--' + (m.role || 'unknown');
      const role = document.createElement('div');
      role.className = 'msg-role';
      role.textContent = m.role || '';
      const body = document.createElement('div');
      body.className = 'msg-body';
      body.innerHTML = renderMarkdownLite(m.content || '');
      wrap.appendChild(role);
      wrap.appendChild(body);
      transcript.appendChild(wrap);
    }
  }

  /* ----------------------------------------- crypto helpers ------------- */

  function importAesKey(raw) {
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
  }

  async function gunzip(bytes) {
    if (typeof DecompressionStream === 'undefined') {
      // Should not happen on any modern browser, but bail loudly.
      throw new Error('this browser does not support DecompressionStream');
    }
    const ds = new DecompressionStream('gzip');
    const stream = new Response(new Blob([bytes]).stream().pipeThrough(ds));
    const buf = await stream.arrayBuffer();
    return new Uint8Array(buf);
  }

  function base64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function base64urlToBytes(s) {
    // base64url → base64 ('-' → '+', '_' → '/', re-pad to multiple of 4)
    let b = s.replace(/-/g, '+').replace(/_/g, '/');
    while (b.length % 4 !== 0) b += '=';
    return base64ToBytes(b);
  }

  function readFragmentKey() {
    const frag = location.hash.startsWith('#') ? location.hash.slice(1) : '';
    if (!frag) return null;
    const params = new URLSearchParams(frag);
    return params.get('k');
  }

  /* ----------------------------------------- UI helpers ---------------- */

  function showError(text) {
    loading.hidden = true;
    gate.hidden = true;
    errorDetail.textContent = text;
    errorSection.hidden = false;
  }
  function showGateError(text) {
    gateError.textContent = text;
    gateError.hidden = false;
  }

  /**
   * Very small markdown renderer covering the common chat cases without
   * adding a 40 KB dependency. Handles fenced code, inline code, bold,
   * italic, links, and preserves paragraphs / newlines.
   */
  function renderMarkdownLite(src) {
    const esc = (s) =>
      s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');

    const codeBlocks = [];
    let preprocessed = src.replace(/```([^\n]*)\n([\s\S]*?)```/g, (_, lang, body) => {
      const idx = codeBlocks.length;
      codeBlocks.push(
        '<pre class="code"><code>' +
          esc(body.replace(/\n$/, '')) +
          '</code></pre>',
      );
      return ` CODE${idx} `;
    });
    void preprocessed;

    let html = esc(preprocessed);
    html = html.replace(/`([^`\n]+)`/g, '<code>$1</code>');
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/(?<![*])\*([^*\n]+)\*(?![*])/g, '<em>$1</em>');
    html = html.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, (_, t, u) => {
      const safeUrl = u.replace(/"/g, '&quot;');
      return `<a href="${safeUrl}" target="_blank" rel="noopener noreferrer">${t}</a>`;
    });

    // Restore code blocks.
    html = html.replace(/ CODE(\d+) /g, (_, n) => codeBlocks[Number(n)]);

    // Paragraph breaks on blank lines; keep single newlines as <br>.
    const paragraphs = html
      .split(/\n{2,}/)
      .map((p) => '<p>' + p.replace(/\n/g, '<br>') + '</p>');
    return paragraphs.join('');
  }
})();
