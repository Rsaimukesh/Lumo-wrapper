import express, { Express, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { initializeDatabase } from './database';
import { logger } from './utils/logger';
import homeRoutes from './routes/home.routes';
import authRoutes from './routes/auth.routes';
import providerRoutes from './routes/provider.routes';
import taskRoutes from './routes/task.routes';
import errorHandler from './middleware/errorHandler';
import { authMiddleware } from './middleware/auth.middleware';

dotenv.config();

const app: Express = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
  credentials: true,
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use((req: Request, _res: Response, next: NextFunction) => {
  logger.info(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Initialize database
(async () => {
  try {
    await initializeDatabase();
    logger.info('Database initialized successfully');
  } catch (error) {
    logger.error('Database initialization failed:', error);
    process.exit(1);
  }
})();

// Routes — auth routes are public, all others require authentication
app.use('/api/auth', authRoutes);
app.use('/api/home', authMiddleware, homeRoutes);
app.use('/api/providers', authMiddleware, providerRoutes);
app.use('/api/tasks', authMiddleware, taskRoutes);

// Health check
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// 404 handler
app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: 'Route not found' });
});

// Error handler
app.use(errorHandler);

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received — shutting down gracefully');
  const { closeDatabase } = require('./database');
  closeDatabase();
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received — shutting down gracefully');
  const { closeDatabase } = require('./database');
  closeDatabase();
  process.exit(0);
});

// Start server
app.listen(PORT, () => {
  logger.info(` Server running on http://localhost:${PORT}`);
});

export default app;
