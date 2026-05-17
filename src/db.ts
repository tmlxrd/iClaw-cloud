/**
 * Mongo connection bootstrap.
 *
 * Single shared mongoose connection. We don't pool ourselves — mongoose's
 * driver does that. Reconnection is automatic via the mongoose driver too;
 * we only log lifecycle events here so operators see what's going on.
 */

import mongoose from 'mongoose';
import { config } from './config';

let connected = false;

export async function connectToDb(): Promise<typeof mongoose> {
  if (connected) return mongoose;

  // Strict query mode prevents typos in filters from silently returning every
  // document. (Default in Mongoose 8 but we lock it for clarity.)
  mongoose.set('strictQuery', true);

  mongoose.connection.on('connected', () => {
    connected = true;
    console.log(
      `[db] connected to ${redactedUrl(config.mongo.url)} → ${config.mongo.dbName}`,
    );
  });
  mongoose.connection.on('disconnected', () => {
    connected = false;
    console.warn('[db] disconnected — mongoose will try to reconnect');
  });
  mongoose.connection.on('error', (err: unknown) => {
    console.error('[db] error', err instanceof Error ? err.message : err);
  });

  await mongoose.connect(config.mongo.url, {
    dbName: config.mongo.dbName,
    // Conservative timeouts — we want fail-fast on misconfig, not 30s hangs.
    serverSelectionTimeoutMS: 10_000,
    socketTimeoutMS: 30_000,
    maxPoolSize: 20,
  });
  return mongoose;
}

export async function disconnectFromDb(): Promise<void> {
  if (!connected) return;
  await mongoose.disconnect();
  connected = false;
}

/** Hide username:password from logs, keep just the host:port + scheme. */
function redactedUrl(url: string): string {
  try {
    const u = new URL(url);
    const host = u.host;
    const proto = u.protocol;
    return `${proto}//***:***@${host}`;
  } catch {
    return '***';
  }
}
