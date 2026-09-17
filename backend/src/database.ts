import Database from 'better-sqlite3';
import path from 'path';
import { logger } from './utils/logger';

let db: Database.Database;

export function getDatabase(): Database.Database {
  if (!db) {
    throw new Error('Database not initialized');
  }
  return db;
}

export async function initializeDatabase(): Promise<void> {
  const dbPath = process.env.DATABASE_PATH || process.env.DATABASE_URL || './data/Lumo.db';
  const fullPath = path.resolve(dbPath);

  try {
    db = new Database(fullPath);
    db.pragma('foreign_keys = ON');
    db.pragma('journal_mode = WAL');

    // Create tables
    createTables();
    
    logger.info(`Database initialized at ${fullPath}`);
  } catch (error) {
    logger.error('Failed to initialize database:', error);
    throw error;
  }
}

function createTables(): void {
  const db = getDatabase();

  // Users table
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      avatar_url TEXT,
      theme TEXT DEFAULT 'dark',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Recent tasks table
  db.exec(`
    CREATE TABLE IF NOT EXISTS recent_tasks (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      goal TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('completed', 'failed', 'in-progress')),
      result TEXT,
      confidence_score REAL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // AI Providers table
  db.exec(`
    CREATE TABLE IF NOT EXISTS ai_providers (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      provider_type TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('connected', 'disconnected', 'error')),
      model TEXT,
      api_key_hash TEXT,
      last_used DATETIME,
      is_default BOOLEAN DEFAULT FALSE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Quick actions table
  db.exec(`
    CREATE TABLE IF NOT EXISTS quick_actions (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      icon TEXT,
      category TEXT NOT NULL,
      action_type TEXT NOT NULL,
      execution_count INTEGER DEFAULT 0,
      last_executed DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Workflow shortcuts table
  db.exec(`
    CREATE TABLE IF NOT EXISTS workflow_shortcuts (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      frequency TEXT NOT NULL,
      enabled BOOLEAN DEFAULT TRUE,
      execution_count INTEGER DEFAULT 0,
      last_executed DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Sessions table
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token TEXT UNIQUE NOT NULL,
      expires_at DATETIME NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  logger.info('All tables created successfully');
}

export function closeDatabase(): void {
  if (db) {
    db.close();
    logger.info('Database connection closed');
  }
}
