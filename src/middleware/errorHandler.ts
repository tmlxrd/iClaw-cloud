/**
 * Last-resort Express error handler.
 *
 * Logs the full error server-side but only returns a sanitised payload to
 * the client (no stack traces in production). 4-arg signature is what Express
 * uses to detect "error middleware" — don't remove `_next` even unused.
 */

import type { ErrorRequestHandler } from 'express';
import { config } from '../config';

export const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  const status =
    typeof (err as { status?: unknown }).status === 'number'
      ? (err as { status: number }).status
      : 500;
  const message =
    err instanceof Error ? err.message : 'internal error';

  console.error(
    `[error] ${req.method} ${req.originalUrl} → ${status} :: ${message}`,
  );
  if (!config.isProduction && err instanceof Error && err.stack) {
    console.error(err.stack);
  }

  if (res.headersSent) return;
  res.status(status).json({
    error: config.isProduction && status >= 500 ? 'internal error' : message,
  });
};
