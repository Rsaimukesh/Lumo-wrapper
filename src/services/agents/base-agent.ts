/**
 * Base Agent Framework
 * Abstract base class for all AI agents in Lumo Browser
 * Provides common interface for agent lifecycle, execution, and communication
 */

import { Logger } from '@utils/logger';
import type { WorkflowAction } from '../../types/index';

export enum AgentStatus {
  IDLE = 'idle',
  THINKING = 'thinking',
  EXECUTING = 'executing',
  COMPLETED = 'completed',
  FAILED = 'failed',
  PAUSED = 'paused'
}

export interface AgentContext {
  conversationId: string;
  sessionId: string;
  pageContext?: {
    url: string;
    title: string;
    content: string;
  };
  previousResults?: WorkflowAction[];
  variables?: Record<string, unknown>;
}

export interface AgentMessage {
  type: 'log' | 'warning' | 'error' | 'result';
  content: string;
  timestamp: number;
}

/**
 * Abstract base class for all AI agents
 * Defines the interface that all agents must implement
 */
export abstract class BaseAgent {
  protected logger: Logger;
  protected agentId: string;
  protected status: AgentStatus = AgentStatus.IDLE;
  protected messages: AgentMessage[] = [];
  protected context?: AgentContext;
  private readonly createdAt: string;

  constructor(agentId: string, agentType: string) {
    this.logger = Logger.getInstance();
    this.agentId = `${agentType}:${agentId}`;
    this.createdAt = new Date().toISOString();
  }

  /**
   * Initialize the agent with context
   */
  public initialize(context: AgentContext): void {
    this.context = context;
    this.logger.info('Agent', `Agent ${this.agentId} initialized`, {
      agentId: this.agentId,
      conversationId: context.conversationId
    });
  }

  /**
   * Get current agent status
   */
  public getStatus(): AgentStatus {
    return this.status;
  }

  /**
   * Get agent messages
   */
  public getMessages(): AgentMessage[] {
    return this.messages;
  }

  /**
   * Clear agent messages
   */
  public clearMessages(): void {
    this.messages = [];
  }

  /**
   * Add a message to the agent's message queue
   */
  protected addMessage(type: AgentMessage['type'], content: string): void {
    const MAX_MESSAGES = 200;
    this.messages.push({
      type,
      content,
      timestamp: Date.now()
    });
    // Cap messages to prevent memory growth
    if (this.messages.length > MAX_MESSAGES) {
      this.messages = this.messages.slice(-MAX_MESSAGES);
    }
  }

  /**
   * Get agent metadata
   */
  public getMetadata(): { id: string; name: string; type: string; status: AgentStatus; createdAt: string } {
    return {
      id: this.agentId,
      name: this.agentId,
      type: 'base',
      status: this.status,
      createdAt: this.createdAt
    };
  }

  /**
   * Execute the agent's primary task
   * Must be implemented by subclasses
   */
  abstract execute(): Promise<unknown>;

  /**
   * Validate preconditions for agent execution
   */
  protected validateContext(): boolean {
    if (!this.context) {
      this.addMessage('error', 'Agent context not initialized');
      return false;
    }
    return true;
  }

  /**
   * Handle errors during execution
   */
  protected handleError(error: Error): void {
    this.status = AgentStatus.FAILED;
    this.addMessage('error', `${error.name}: ${error.message}`);
    this.logger.error('Agent', `Agent ${this.agentId} failed`, {
      error: error.message,
      stack: error.stack
    });
  }

  /**
   * Reset agent to idle state
   */
  public reset(): void {
    this.status = AgentStatus.IDLE;
    this.clearMessages();
    this.context = undefined;
    this.logger.debug('Agent', `Agent ${this.agentId} reset`, {
      agentId: this.agentId
    });
  }
}
