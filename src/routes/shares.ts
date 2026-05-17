/**
 * /api/shares routes.
 *
 *   POST /api/shares
 *     Body: { ciphertext, nonce, salt?, wrappedKey?, hasPassword,
 *             ttlDays, maxViews? }
 *     All binary fields are base64 strings on the wire.
 *     Response: { id, url, expiresAt }
 *
 *   GET /api/shares/:id
 *     Response: { ciphertext, nonce, salt?, wrappedKey?, hasPassword,
 *                 viewCount, maxViews, expiresAt }
 *     If maxViews is set and reached after this read, the doc is deleted.
 *
 * Routes never touch the cleartext. They validate sizes/shapes, write the
 * blob, and return enough metadata for the client viewer to do its work.
 */

import { Router } from 'express';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { Share } from '../models/Share';
import { config } from '../config';
import { createLimiter, readLimiter } from '../middleware/rateLimit';

export const sharesRouter: Router = Router();

/* ----------------------------------------------------- helpers --------- */

const Base64Bytes = z
  .string()
  .min(1)
  .max(Math.ceil((config.limits.maxPayloadBytes * 4) / 3) + 32)
  .regex(/^[A-Za-z0-9+/=_-]+$/, 'must be base64 / base64url');

function decodeBase64ToBuffer(raw: string, max: number): Buffer {
  const buf = Buffer.from(raw, 'base64');
  if (buf.length === 0) throw new HttpError(400, 'empty binary field');
  if (buf.length > max) throw new HttpError(413, `binary field too large (> ${max} bytes)`);
  return buf;
}

function sha256Hex(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/* ----------------------------------------------------- POST /api/shares -- */

const CreateShareBodySchema = z.object({
  ciphertext: Base64Bytes,
  nonce: Base64Bytes,
  salt: Base64Bytes.optional().nullable(),
  wrappedKey: Base64Bytes.optional().nullable(),
  hasPassword: z.boolean(),
  ttlDays: z.number().int().min(config.ttl.minDays).max(config.ttl.maxDays),
  maxViews: z.number().int().positive().max(1000).optional().nullable(),
});

sharesRouter.post('/', createLimiter, async (req, res, next) => {
  try {
    const parsed = CreateShareBodySchema.safeParse(req.body);
    if (!parsed.success) {
      const detail = parsed.error.issues
        .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`)
        .join('; ');
      throw new HttpError(400, `invalid body — ${detail}`);
    }
    const body = parsed.data;

    // Decode + size-check every binary field independently.
    const ciphertext = decodeBase64ToBuffer(body.ciphertext, config.limits.maxPayloadBytes);
    const nonce = decodeBase64ToBuffer(body.nonce, 64);
    const salt =
      body.salt != null
        ? decodeBase64ToBuffer(body.salt, 64)
        : null;
    const wrappedKey =
      body.wrappedKey != null
        ? decodeBase64ToBuffer(body.wrappedKey, 256)
        : null;

    // Password contract: either fully set (salt + wrappedKey + hasPassword=true)
    // or fully unset. No half-states allowed.
    if (body.hasPassword) {
      if (!salt || !wrappedKey) {
        throw new HttpError(400, 'hasPassword=true requires both salt and wrappedKey');
      }
    } else {
      if (salt || wrappedKey) {
        throw new HttpError(400, 'salt/wrappedKey only allowed when hasPassword=true');
      }
    }

    const now = Date.now();
    const expiresAt = new Date(now + body.ttlDays * 24 * 60 * 60 * 1000);

    const creatorIpHash =
      typeof req.ip === 'string' && req.ip ? sha256Hex(req.ip) : null;

    const doc = await Share.create({
      ciphertext,
      nonce,
      salt,
      wrappedKey,
      hasPassword: body.hasPassword,
      maxViews: body.maxViews ?? null,
      expiresAt,
      size: ciphertext.length,
      creatorIpHash,
    });

    if (config.logAccess) {
      console.log(
        `[shares] CREATE id=${doc._id} size=${ciphertext.length} ttl=${body.ttlDays}d` +
          ` maxViews=${body.maxViews ?? '-'} ip=${creatorIpHash?.slice(0, 8) ?? '-'}`,
      );
    }

    res.status(201).json({
      id: doc._id,
      url: `${config.baseUrl}/s/${doc._id}`,
      expiresAt: doc.expiresAt.toISOString(),
    });
  } catch (err) {
    next(err);
  }
});

/* ----------------------------------------------------- GET /api/shares/:id */

sharesRouter.get('/:id', readLimiter, async (req, res, next) => {
  try {
    const id = String(req.params.id || '').trim();
    if (!/^[A-Za-z0-9_-]{6,32}$/.test(id)) {
      throw new HttpError(400, 'invalid id');
    }
    const doc = await Share.findById(id);
    if (!doc) {
      throw new HttpError(404, 'not found or expired');
    }

    // Defensive belt-and-braces: TTL index runs once a minute so a tiny window
    // exists where an expired doc could still be fetched. Block that.
    if (doc.expiresAt.getTime() <= Date.now()) {
      // Best-effort cleanup; ignore failure.
      await Share.deleteOne({ _id: id }).catch(() => {});
      throw new HttpError(404, 'not found or expired');
    }

    // Atomic increment so concurrent reads don't both see "last view".
    const updated = await Share.findOneAndUpdate(
      { _id: id },
      { $inc: { viewCount: 1 } },
      { new: true, projection: { __v: 0 } },
    );
    if (!updated) {
      // Someone deleted it between our find and update.
      throw new HttpError(404, 'not found or expired');
    }

    const burned =
      updated.maxViews != null && updated.viewCount >= updated.maxViews;

    if (config.logAccess) {
      console.log(
        `[shares] READ id=${id} view=${updated.viewCount}/${updated.maxViews ?? '∞'} burned=${burned}`,
      );
    }

    // Return BEFORE deleting so the requester actually gets the payload.
    const payload = {
      ciphertext: Buffer.from(updated.ciphertext).toString('base64'),
      nonce: Buffer.from(updated.nonce).toString('base64'),
      salt: updated.salt ? Buffer.from(updated.salt).toString('base64') : null,
      wrappedKey: updated.wrappedKey
        ? Buffer.from(updated.wrappedKey).toString('base64')
        : null,
      hasPassword: updated.hasPassword,
      viewCount: updated.viewCount,
      maxViews: updated.maxViews,
      expiresAt: updated.expiresAt.toISOString(),
    };

    if (burned) {
      await Share.deleteOne({ _id: id }).catch((err) => {
        console.error('[shares] burn-after-read delete failed', err);
      });
    }

    res.json(payload);
  } catch (err) {
    next(err);
  }
});
