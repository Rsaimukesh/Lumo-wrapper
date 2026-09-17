import { Router, Request, Response } from 'express';
import { getDatabase } from '../database';
import { HomePageData, Task, AIProvider, QuickAction, Workflow } from '../types';
import { logger } from '../utils/logger';
import { v4 as uuidv4 } from 'uuid';

const router = Router();

// Get home page data for authenticated user
router.get('/data', (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    // Get recent tasks
    const recentTasks = db
      .prepare(`
        SELECT * FROM recent_tasks 
        WHERE user_id = ? 
        ORDER BY timestamp DESC 
        LIMIT 10
      `)
      .all(userId) as Task[];

    // Get AI providers
    const aiProviders = db
      .prepare(`
        SELECT id, user_id, name, provider_type, status, model, last_used, is_default, created_at, updated_at 
        FROM ai_providers 
        WHERE user_id = ?
      `)
      .all(userId) as AIProvider[];

    // Get suggested actions
    const suggestedActions = db
      .prepare(`
        SELECT * FROM quick_actions 
        WHERE user_id IS NULL OR user_id = ?
        LIMIT 6
      `)
      .all(userId) as QuickAction[];

    // Get workflows
    const workflows = db
      .prepare(`
        SELECT * FROM workflow_shortcuts 
        WHERE user_id = ? AND enabled = TRUE
      `)
      .all(userId) as Workflow[];

    const data: HomePageData = {
      recentTasks,
      suggestedActions,
      aiProviders,
      workflows,
      systemStatus: 'ready',
    };

    res.json({
      data,
      timestamp: new Date().toISOString(),
    });

    logger.info('Home page data retrieved', { userId, tasksCount: recentTasks.length });
  } catch (error) {
    logger.error('Error fetching home page data:', error);
    res.status(500).json({ error: 'Failed to fetch home page data' });
  }
});

// Execute a quick action
router.post('/action/:actionId/execute', (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const { actionId } = req.params;
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    // Get action
    const action = db
      .prepare('SELECT * FROM quick_actions WHERE id = ?')
      .get(actionId) as QuickAction | undefined;

    if (!action) {
      res.status(404).json({ error: 'Action not found' });
      return;
    }

    // Update execution count and last executed time
    db.prepare(`
      UPDATE quick_actions 
      SET execution_count = execution_count + 1, 
          last_executed = CURRENT_TIMESTAMP 
      WHERE id = ?
    `).run(actionId);

    // Create a new task
    const taskId = uuidv4();
    db.prepare(`
      INSERT INTO recent_tasks (id, user_id, goal, status, timestamp)
      VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).run(taskId, userId, action.title, 'in-progress');

    res.json({
      data: { taskId, actionId, executed: true },
      message: `Action "${action.title}" executed`,
      timestamp: new Date().toISOString(),
    });

    logger.info('Quick action executed', { actionId, taskId });
  } catch (error) {
    logger.error('Error executing action:', error);
    res.status(500).json({ error: 'Failed to execute action' });
  }
});

// Execute workflow
router.post('/workflow/:workflowId/execute', (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const { workflowId } = req.params;

    // Get workflow
    const workflow = db
      .prepare('SELECT * FROM workflow_shortcuts WHERE id = ?')
      .get(workflowId) as Workflow | undefined;

    if (!workflow) {
      res.status(404).json({ error: 'Workflow not found' });
      return;
    }

    // Update workflow execution
    db.prepare(`
      UPDATE workflow_shortcuts 
      SET execution_count = execution_count + 1, 
          last_executed = CURRENT_TIMESTAMP 
      WHERE id = ?
    `).run(workflowId);

    res.json({
      data: { workflowId, executed: true },
      message: `Workflow "${workflow.name}" queued for execution`,
      timestamp: new Date().toISOString(),
    });

    logger.info('Workflow executed', { workflowId });
  } catch (error) {
    logger.error('Error executing workflow:', error);
    res.status(500).json({ error: 'Failed to execute workflow' });
  }
});

// Search endpoint
router.post('/search', (req: Request, res: Response) => {
  try {
    const { query } = req.body;
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    if (!query) {
      res.status(400).json({ error: 'Query is required' });
      return;
    }

    // Create a new task for the search
    const taskId = uuidv4();
    const db = getDatabase();
    db.prepare(`
      INSERT INTO recent_tasks (id, user_id, goal, status, timestamp)
      VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).run(taskId, userId, query, 'in-progress');

    res.json({
      data: { taskId, query, status: 'in-progress' },
      message: 'Search initiated',
      timestamp: new Date().toISOString(),
    });

    logger.info('Search initiated', { taskId, query });
  } catch (error) {
    logger.error('Error processing search:', error);
    res.status(500).json({ error: 'Failed to process search' });
  }
});

export default router;