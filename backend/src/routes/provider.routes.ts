import { Router, Request, Response } from 'express';
import { getDatabase } from '../database';
import { AIProvider } from '../types';
import { logger } from '../utils/logger';
import { v4 as uuidv4 } from 'uuid';

const router = Router();

// Get all providers for user
router.get('/', (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const providers = db
      .prepare(`
        SELECT id, user_id, name, provider_type, status, model, last_used, is_default, created_at, updated_at
        FROM ai_providers 
        WHERE user_id = ?
        ORDER BY is_default DESC, created_at DESC
      `)
      .all(userId) as AIProvider[];

    res.json({
      data: providers,
      timestamp: new Date().toISOString(),
    });

    logger.info('Providers fetched', { userId, count: providers.length });
  } catch (error) {
    logger.error('Error fetching providers:', error);
    res.status(500).json({ error: 'Failed to fetch providers' });
  }
});

// Add new provider
router.post('/', (req: Request, res: Response) => {
  try {
    const { name, provider_type, model, api_key } = req.body;
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    const db = getDatabase();

    if (!name || !provider_type) {
      res.status(400).json({ error: 'Name and provider_type are required' });
      return;
    }

    const providerId = uuidv4();

    db.prepare(`
      INSERT INTO ai_providers (id, user_id, name, provider_type, status, model, api_key_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(providerId, userId, name, provider_type, 'connected', model || null, api_key || null);

    const provider = {
      id: providerId,
      user_id: userId,
      name,
      provider_type,
      status: 'connected',
      model: model || null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    res.status(201).json({
      data: provider,
      message: 'Provider added successfully',
      timestamp: new Date().toISOString(),
    });

    logger.info('Provider added', { providerId, name });
  } catch (error) {
    logger.error('Error adding provider:', error);
    res.status(500).json({ error: 'Failed to add provider' });
  }
});

// Update provider status
router.patch('/:providerId/status', (req: Request, res: Response) => {
  try {
    const { providerId } = req.params;
    const { status } = req.body;
    const db = getDatabase();

    if (!['connected', 'disconnected', 'error'].includes(status)) {
      res.status(400).json({ error: 'Invalid status' });
      return;
    }

    db.prepare('UPDATE ai_providers SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(status, providerId);

    res.json({
      data: { providerId, status },
      message: 'Provider status updated',
      timestamp: new Date().toISOString(),
    });

    logger.info('Provider status updated', { providerId, status });
  } catch (error) {
    logger.error('Error updating provider status:', error);
    res.status(500).json({ error: 'Failed to update provider' });
  }
});

// Delete provider
router.delete('/:providerId', (req: Request, res: Response) => {
  try {
    const { providerId } = req.params;
    const db = getDatabase();

    db.prepare('DELETE FROM ai_providers WHERE id = ?').run(providerId);

    res.json({
      data: { providerId },
      message: 'Provider deleted',
      timestamp: new Date().toISOString(),
    });

    logger.info('Provider deleted', { providerId });
  } catch (error) {
    logger.error('Error deleting provider:', error);
    res.status(500).json({ error: 'Failed to delete provider' });
  }
});

export default router;
