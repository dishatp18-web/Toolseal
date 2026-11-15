import crypto from 'crypto';
import type { CookieOptions, NextFunction, Request, Response } from 'express';
import { db, uid } from '../db/database.ts';
import { hashPassword, verifyPassword } from './password.ts';
import type { UserRecord } from '../../types/toolseal.ts';

export { hashPassword, verifyPassword };

export const SESSION_COOKIE_NAME = 'toolseal_session';

declare global {
  namespace Express {
    interface Request {
      authUser?: UserRecord;
      sessionToken?: string;
      rawBody?: Buffer;
    }
  }
}

function getSessionTtlHours(): number {
  const parsed = Number(process.env.TOOLSEAL_SESSION_TTL_HOURS);
  if (Number.isFinite(parsed) && parsed >= 1 && parsed <= 168) {
    return parsed;
  }
  return 24;
}

export function hashSessionToken(token: string): string {
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

export function createSession(userId: string): { token: string; expiresAt: string } {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashSessionToken(token);
  const ttlHours = getSessionTtlHours();
  const expiresAtDate = new Date(Date.now() + ttlHours * 3600 * 1000);
  const expiresAt = expiresAtDate.toISOString();

  db.prepare(`
    INSERT INTO user_sessions (id, user_id, token_hash, expires_at)
    VALUES (?, ?, ?, ?)
  `).run(uid('sess'), userId, tokenHash, expiresAt);

  // Clean up expired sessions opportunistically
  db.prepare(`DELETE FROM user_sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL`).run(
    new Date(Date.now() - 24 * 3600 * 1000).toISOString()
  );

  return { token, expiresAt };
}

export function revokeSession(token: string) {
  const tokenHash = hashSessionToken(token);
  db.prepare(`UPDATE user_sessions SET revoked_at = datetime('now') WHERE token_hash = ?`).run(tokenHash);
}

export function resolveSessionUser(token: string | null | undefined): UserRecord | null {
  if (!token || token.length < 32) return null;
  const tokenHash = hashSessionToken(token);
  const nowIso = new Date().toISOString();

  const row = db
    .prepare(
      `
      SELECT u.id, u.username, u.email, u.role, u.display_name, u.is_active, u.created_at
      FROM user_sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?
        AND s.revoked_at IS NULL
        AND s.expires_at > ?
        AND COALESCE(u.is_active, 1) = 1
      LIMIT 1
    `
    )
    .get(tokenHash, nowIso) as UserRecord | undefined;

  return row ?? null;
}

export function extractSessionTokenFromCookieHeader(cookieHeader: string | undefined): string | null {
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split(';');
  for (const part of cookies) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key === SESSION_COOKIE_NAME && val) {
      try {
        return decodeURIComponent(val);
      } catch {
        return val;
      }
    }
  }
  return null;
}

export function extractSessionTokensFromRequest(req: Request): string[] {
  const tokens: string[] = [];
  const authHeader = req.headers.authorization;
  if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    const bearer = authHeader.slice(7).trim();
    if (bearer) tokens.push(bearer);
  }
  const cookieToken = extractSessionTokenFromCookieHeader(req.headers.cookie);
  if (cookieToken && !tokens.includes(cookieToken)) {
    tokens.push(cookieToken);
  }
  return tokens;
}

export function extractSessionTokenFromRequest(req: Request): string | null {
  return extractSessionTokensFromRequest(req)[0] ?? null;
}

export function extractSessionTokenFromWsRequest(headers: {
  cookie?: string;
  'sec-websocket-protocol'?: string | string[];
}): string | null {
  const protoHeader = headers['sec-websocket-protocol'];
  const rawProto = Array.isArray(protoHeader) ? protoHeader.join(',') : protoHeader;
  if (rawProto) {
    for (const part of rawProto.split(',')) {
      const trimmed = part.trim();
      if (trimmed.startsWith('toolseal-bearer.')) {
        const token = trimmed.slice('toolseal-bearer.'.length).trim();
        if (token.length >= 32) return token;
      }
    }
  }
  return extractSessionTokenFromCookieHeader(headers.cookie);
}

export function resolveSessionFromRequest(req: Request): { user: UserRecord; token: string } | null {
  for (const token of extractSessionTokensFromRequest(req)) {
    const user = resolveSessionUser(token);
    if (user) {
      return { user, token };
    }
  }
  return null;
}

function isSecureRequest(req: Request): boolean {
  if (req.secure) return true;
  const xfProto = req.headers['x-forwarded-proto'];
  if (typeof xfProto === 'string' && xfProto.split(',')[0].trim() === 'https') return true;
  const origin = req.headers.origin;
  if (typeof origin === 'string' && origin.startsWith('https://')) return true;
  return false;
}

type SessionCookieOptions = CookieOptions & { partitioned?: boolean };

export function setSessionCookie(res: Response, req: Request, token: string, expiresAtIso: string) {
  const maxAgeMs = Math.max(0, new Date(expiresAtIso).getTime() - Date.now());
  const secure = isSecureRequest(req);
  const options: SessionCookieOptions = {
    httpOnly: true,
    sameSite: secure ? 'none' : 'lax',
    secure,
    path: '/',
    maxAge: maxAgeMs,
  };
  if (secure) {
    options.partitioned = true;
  }
  res.cookie(SESSION_COOKIE_NAME, token, options);
}

export function clearSessionCookie(res: Response, req: Request) {
  const secure = isSecureRequest(req);
  const options: SessionCookieOptions = {
    httpOnly: true,
    sameSite: secure ? 'none' : 'lax',
    secure,
    path: '/',
  };
  if (secure) {
    options.partitioned = true;
  }
  res.clearCookie(SESSION_COOKIE_NAME, options);
}

/**
 * Express middleware enforcing an active database-backed user session.
 * Role and identity are ALWAYS resolved from SQLite, never from request body/headers.
 */
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const resolved = resolveSessionFromRequest(req);
  if (!resolved) {
    res.status(401).json({
      error: 'Authentication required. Please sign in with a valid TOOLSEAL account.',
      code: 'UNAUTHENTICATED',
    });
    return;
  }
  req.authUser = resolved.user;
  req.sessionToken = resolved.token;
  next();
}

/**
 * Express middleware enforcing role-based authorization from the authenticated database user.
 */
export function requireRole(...allowedRoles: Array<UserRecord['role']>) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.authUser) {
      res.status(401).json({
        error: 'Authentication required.',
        code: 'UNAUTHENTICATED',
      });
      return;
    }
    if (!allowedRoles.includes(req.authUser.role)) {
      res.status(403).json({
        error: `Forbidden: "${req.authUser.role}" role cannot perform this action. Required: ${allowedRoles.join(' or ')}.`,
        code: 'FORBIDDEN',
      });
      return;
    }
    next();
  };
}
