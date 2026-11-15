import crypto from 'crypto';
import type { NextFunction, Request, Response } from 'express';
import { db } from '../db/database.ts';
import { logBifrostEvent } from './adapter.ts';

export function getBifrostSharedSecret(): string {
  return (process.env.BIFROST_SHARED_SECRET || '').trim();
}

export function getBifrostSignatureTtlSeconds(): number {
  const parsed = Number(process.env.BIFROST_SIGNATURE_TTL_SECONDS);
  if (Number.isFinite(parsed) && parsed >= 30 && parsed <= 3600) {
    return Math.round(parsed);
  }
  return 300;
}

/**
 * Computes HMAC-SHA256 signature over `${timestamp}.${nonce}.${rawBody}`.
 */
export function signBifrostPayload(
  rawBody: string | Buffer,
  timestampSec: number | string,
  nonce: string,
  secret: string
): string {
  const bodyStr = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
  const canonical = `${timestampSec}.${nonce}.${bodyStr}`;
  const digest = crypto.createHmac('sha256', secret).update(canonical, 'utf8').digest('hex');
  return `sha256=${digest}`;
}

export interface WebhookVerificationInput {
  rawBody: string | Buffer;
  timestampHeader?: string;
  nonceHeader?: string;
  signatureHeader?: string;
  secretOverride?: string;
  ttlSecondsOverride?: number;
  nowSecondsOverride?: number;
}

export interface WebhookVerificationResult {
  ok: boolean;
  status: number;
  code:
    | 'OK'
    | 'SECRET_UNCONFIGURED'
    | 'MISSING_SIGNATURE'
    | 'EXPIRED_TIMESTAMP'
    | 'INVALID_SIGNATURE'
    | 'REPLAY_DETECTED';
  error?: string;
}

/**
 * Verifies Bifrost webhook HMAC-SHA256 signature, timestamp window, and SQLite-backed replay nonce.
 * Never logs or returns secret values.
 */
export function verifyBifrostWebhookRequest(input: WebhookVerificationInput): WebhookVerificationResult {
  const secret = (input.secretOverride ?? getBifrostSharedSecret()).trim();
  if (!secret) {
    return {
      ok: false,
      status: 503,
      code: 'SECRET_UNCONFIGURED',
      error: 'Webhook authentication rejected: BIFROST_SHARED_SECRET is not configured in backend environment.',
    };
  }

  const tsRaw = input.timestampHeader?.trim();
  const nonce = input.nonceHeader?.trim();
  const sigRaw = input.signatureHeader?.trim();

  if (!tsRaw || !nonce || !sigRaw) {
    return {
      ok: false,
      status: 401,
      code: 'MISSING_SIGNATURE',
      error: 'Missing required Bifrost authentication headers (X-Bifrost-Timestamp, X-Bifrost-Nonce, X-Bifrost-Signature).',
    };
  }

  if (nonce.length < 8 || nonce.length > 128) {
    return {
      ok: false,
      status: 401,
      code: 'MISSING_SIGNATURE',
      error: 'Invalid X-Bifrost-Nonce length.',
    };
  }

  const timestampSec = Number(tsRaw);
  if (!Number.isFinite(timestampSec) || !Number.isInteger(timestampSec) || timestampSec <= 0) {
    return {
      ok: false,
      status: 401,
      code: 'EXPIRED_TIMESTAMP',
      error: 'Invalid X-Bifrost-Timestamp format; expected Unix epoch seconds.',
    };
  }

  const ttlSeconds = input.ttlSecondsOverride ?? getBifrostSignatureTtlSeconds();
  const nowSec = input.nowSecondsOverride ?? Math.floor(Date.now() / 1000);
  const ageSec = nowSec - timestampSec;

  // Allow up to 60s minor forward clock skew, reject expired requests older than ttlSeconds
  if (ageSec > ttlSeconds || ageSec < -60) {
    return {
      ok: false,
      status: 401,
      code: 'EXPIRED_TIMESTAMP',
      error: `Webhook timestamp expired or outside ±${ttlSeconds}s validity window (age=${ageSec}s).`,
    };
  }

  // Normalize signature ("sha256=<64hex>" or "<64hex>")
  const normalizedHex = sigRaw.startsWith('sha256=') ? sigRaw.slice(7).toLowerCase() : sigRaw.toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(normalizedHex)) {
    return {
      ok: false,
      status: 401,
      code: 'INVALID_SIGNATURE',
      error: 'Malformed HMAC-SHA256 signature format.',
    };
  }

  const expectedFull = signBifrostPayload(input.rawBody, timestampSec, nonce, secret);
  const expectedHex = expectedFull.slice(7);

  const expectedBuf = Buffer.from(expectedHex, 'hex');
  const providedBuf = Buffer.from(normalizedHex, 'hex');

  if (expectedBuf.length !== providedBuf.length || !crypto.timingSafeEqual(expectedBuf, providedBuf)) {
    return {
      ok: false,
      status: 401,
      code: 'INVALID_SIGNATURE',
      error: 'HMAC-SHA256 signature verification failed.',
    };
  }

  // Persistent replay protection via SQLite nonce cache
  const nowIso = new Date().toISOString();
  db.prepare('DELETE FROM webhook_replay_nonces WHERE expires_at <= ?').run(nowIso);

  const nonceHash = crypto
    .createHash('sha256')
    .update(`${timestampSec}:${nonce}:${normalizedHex}`, 'utf8')
    .digest('hex');

  const existing = db
    .prepare('SELECT nonce_hash FROM webhook_replay_nonces WHERE nonce_hash = ? LIMIT 1')
    .get(nonceHash) as { nonce_hash: string } | undefined;

  if (existing) {
    return {
      ok: false,
      status: 401,
      code: 'REPLAY_DETECTED',
      error: 'Webhook replay detected: nonce/signature already consumed within validity window.',
    };
  }

  const expiresAt = new Date((nowSec + ttlSeconds + 60) * 1000).toISOString();
  db.prepare(`
    INSERT INTO webhook_replay_nonces (nonce_hash, expires_at)
    VALUES (?, ?)
  `).run(nonceHash, expiresAt);

  return { ok: true, status: 200, code: 'OK' };
}

/**
 * Express middleware authenticating incoming Bifrost PreMCPHook & PostMCPHook webhook calls.
 */
export function requireBifrostWebhookAuth(req: Request, res: Response, next: NextFunction) {
  const rawBody = req.rawBody ?? Buffer.from(JSON.stringify(req.body ?? {}), 'utf8');
  const result = verifyBifrostWebhookRequest({
    rawBody,
    timestampHeader: req.header('x-bifrost-timestamp'),
    nonceHeader: req.header('x-bifrost-nonce'),
    signatureHeader: req.header('x-bifrost-signature'),
  });

  if (!result.ok) {
    logBifrostEvent({
      hookType: 'AdapterEvent',
      sourceMode: 'live',
      toolName: typeof req.body?.tool_name === 'string' ? req.body.tool_name : null,
      decision: result.code,
      statusCode: result.status,
      message: result.error || 'Bifrost webhook authentication rejected.',
      payload: {
        path: req.path,
        code: result.code,
        hasTimestamp: Boolean(req.header('x-bifrost-timestamp')),
        hasNonce: Boolean(req.header('x-bifrost-nonce')),
        hasSignature: Boolean(req.header('x-bifrost-signature')),
      },
    });
    res.status(result.status).json({
      error: result.error,
      code: result.code,
    });
    return;
  }

  next();
}
