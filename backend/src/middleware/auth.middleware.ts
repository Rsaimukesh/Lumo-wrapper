import { Request, Response, NextFunction } from 'express';
import { getDatabase } from '../database';
import { logger } from '../utils/logger';

// Extend Request to include userId
declare global {
  namespace Express {
    interface Request {
      userId?: string;
    }
  }
}

/**
 * Authentication middleware — validates Bearer token from Authorization header
 * and attaches userId to the request.
 */
export function authMiddleware(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing or invalid Authorization header' });
    return;
  }

  const token = authHeader.substring(7);

  try {
    const db = getDatabase();

    // Find session by token and check expiry
    const session = db
      .prepare(`
        SELECT user_id, expires_at FROM sessions
        WHERE token = ? AND expires_at > datetime('now')
      `)
      .get(token) as { user_id: string; expires_at: string } | undefined;

    if (!session) {
      res.status(401).json({ error: 'Invalid or expired token' });
      return;
    }

    req.userId = session.user_id;
    next();
  } catch (error) {
    logger.error('Auth middleware error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
}
