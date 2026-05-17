/**
 * Per-IP rate limits.
 *
 * Two separate limiters:
 *   - createLimiter: throttles POST /api/shares (one creation budget per hour).
 *   - readLimiter:   throttles GET  /api/shares/:id (cheap requests, generous).
 *
 * Both key off `req.ip`, which respects `app.set('trust proxy', …)` in
 * index.ts when running behind a reverse proxy.
 */

import rateLimit from 'express-rate-limit';
import { config } from '../config';

export const createLimiter = rateLimit({
  windowMs: 60 * 60_000, // 1 hour
  limit: config.limits.createPerIpPerHour,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'too many shares created from this IP — slow down a bit' },
});

export const readLimiter = rateLimit({
  windowMs: 60_000, // 1 minute
  limit: config.limits.readPerIpPerMinute,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'too many reads from this IP' },
});
