import { Router, Request, Response } from 'express';
import { getDatabase } from '../database';
import { Task } from '../types';
import { logger } from '../utils/logger';
import { v4 as uuidv4 } from 'uuid';

const router = Router();

// Get all tasks for user
router.get('/', (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    const limit = Math.min(parseInt(req.query.limit as string) || 10, 100);

    const tasks = db
      .prepare(`
        SELECT * FROM recent_tasks 
        WHERE user_id = ?
        ORDER BY timestamp DESC 
        LIMIT ?
      `)
      .all(userId, limit) as Task[];

    res.json({
      data: tasks,
      timestamp: new Date().toISOString(),
    });

    logger.info('Tasks fetched', { userId, count: tasks.length });
  } catch (error) {
    logger.error('Error fetching tasks:', error);
    res.status(500).json({ error: 'Failed to fetch tasks' });
  }
});

// Get task by ID
router.get('/:taskId', (req: Request, res: Response) => {
  try {
    const { taskId } = req.params;
    const db = getDatabase();

    const task = db
      .prepare('SELECT * FROM recent_tasks WHERE id = ?')
      .get(taskId) as Task | undefined;

    if (!task) {
      res.status(404).json({ error: 'Task not found' });
      return;
    }

    res.json({
      data: task,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error('Error fetching task:', error);
    res.status(500).json({ error: 'Failed to fetch task' });
  }
});

// Create task
router.post('/', (req: Request, res: Response) => {
  try {
    const { goal, status = 'in-progress' } = req.body;
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    const db = getDatabase();

    if (!goal) {
      res.status(400).json({ error: 'Goal is required' });
      return;
    }

    const taskId = uuidv4();

    db.prepare(`
      INSERT INTO recent_tasks (id, user_id, goal, status, timestamp)
      VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).run(taskId, userId, goal, status);

    const task: Task = {
      id: taskId,
      user_id: userId,
      goal,
      status,
      timestamp: new Date().toISOString(),
      created_at: new Date().toISOString(),
    };

    res.status(201).json({
      data: task,
      message: 'Task created',
      timestamp: new Date().toISOString(),
    });

    logger.info('Task created', { taskId, goal });
  } catch (error) {
    logger.error('Error creating task:', error);
    res.status(500).json({ error: 'Failed to create task' });
  }
});

// Update task
router.patch('/:taskId', (req: Request, res: Response) => {
  try {
    const { taskId } = req.params;
    const { status, result, confidence_score } = req.body;
    const db = getDatabase();

    // Get existing task
    const task = db
      .prepare('SELECT * FROM recent_tasks WHERE id = ?')
      .get(taskId) as Task | undefined;

    if (!task) {
      res.status(404).json({ error: 'Task not found' });
      return;
    }

    // Update task
    const updateStatus = status || task.status;
    const updateResult = result || task.result;
    const updateConfidence = confidence_score !== undefined ? confidence_score : task.confidence_score;

    db.prepare(`
      UPDATE recent_tasks 
      SET status = ?, result = ?, confidence_score = ?
      WHERE id = ?
    `).run(updateStatus, updateResult, updateConfidence, taskId);

    res.json({
      data: { taskId, status: updateStatus, result: updateResult, confidence_score: updateConfidence },
      message: 'Task updated',
      timestamp: new Date().toISOString(),
    });

    logger.info('Task updated', { taskId, status: updateStatus });
  } catch (error) {
    logger.error('Error updating task:', error);
    res.status(500).json({ error: 'Failed to update task' });
  }
});

// Delete task
router.delete('/:taskId', (req: Request, res: Response) => {
  try {
    const { taskId } = req.params;
    const db = getDatabase();

    db.prepare('DELETE FROM recent_tasks WHERE id = ?').run(taskId);

    res.json({
      data: { taskId },
      message: 'Task deleted',
      timestamp: new Date().toISOString(),
    });

    logger.info('Task deleted', { taskId });
  } catch (error) {
    logger.error('Error deleting task:', error);
    res.status(500).json({ error: 'Failed to delete task' });
  }
});

export default router;
