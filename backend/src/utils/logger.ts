enum LogLevel {
  DEBUG = 'DEBUG',
  INFO = 'INFO',
  WARN = 'WARN',
  ERROR = 'ERROR',
}

// Numeric values for correct level comparison
const LOG_LEVEL数值: Record<LogLevel, number> = {
  [LogLevel.DEBUG]: 0,
  [LogLevel.INFO]: 1,
  [LogLevel.WARN]: 2,
  [LogLevel.ERROR]: 3,
};

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  data?: unknown;
}

class Logger {
  private logLevel: LogLevel;
  private level数值: number;

  constructor(level: string = process.env.LOG_LEVEL || 'INFO') {
    this.logLevel = (LogLevel as any)[level.toUpperCase()] || LogLevel.INFO;
    this.level数值 = LOG_LEVEL数值[this.logLevel];
  }

  private shouldLog(level: LogLevel): boolean {
    return LOG_LEVEL数值[level] >= this.level数值;
  }

  private log(level: LogLevel, message: string, data?: unknown): void {
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
    };

    if (data) {
      (entry as any).data = data;
    }

    console.log(JSON.stringify(entry));
  }

  debug(message: string, data?: unknown): void {
    if (this.shouldLog(LogLevel.DEBUG)) {
      this.log(LogLevel.DEBUG, message, data);
    }
  }

  info(message: string, data?: unknown): void {
    if (this.shouldLog(LogLevel.INFO)) {
      this.log(LogLevel.INFO, message, data);
    }
  }

  warn(message: string, data?: unknown): void {
    if (this.shouldLog(LogLevel.WARN)) {
      this.log(LogLevel.WARN, message, data);
    }
  }

  error(message: string, data?: unknown): void {
    if (this.shouldLog(LogLevel.ERROR)) {
      this.log(LogLevel.ERROR, message, data);
    }
  }
}

export const logger = new Logger();
