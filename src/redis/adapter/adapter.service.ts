import { IoAdapter } from '@nestjs/platform-socket.io';
import { ServerOptions } from 'socket.io';
import { createAdapter } from '@socket.io/redis-adapter';
import { Redis, RedisOptions } from 'ioredis';
import { Logger } from '@nestjs/common';

/**
 * Redis adapter for Socket.IO with automatic reconnection and error handling.
 * Uses ioredis for robust connection management.
 */
export class RedisIoAdapter extends IoAdapter {
  private adapterConstructor!: ReturnType<typeof createAdapter>;
  private readonly logger = new Logger(RedisIoAdapter.name);
  private pubClient!: Redis;
  private subClient!: Redis;
  private isConnecting = false;
  private isClosed = false;

  async connectToRedis(): Promise<void> {
    if (!process.env.REDIS_URL) {
      throw new Error('REDIS_URL is not defined');
    }

    if (this.isConnecting) {
      this.logger.warn(
        'Redis connection already in progress',
        'connectToRedis',
      );
      return;
    }

    this.isConnecting = true;

    try {
      const redisUrl = process.env.REDIS_URL;
      const options: RedisOptions = {
        retryStrategy: (times) => {
          const maxDelay = 30000;
          const delay = Math.min(times * 1000, maxDelay);
          this.logger.warn(
            `Redis reconnecting... Attempt ${times}, waiting ${delay}ms`,
            'connectToRedis',
          );
          return delay;
        },
        maxRetriesPerRequest: null, // Recommended for pub/sub
        enableReadyCheck: true,
      };

      // Create two separate connections for Pub and Sub
      this.pubClient = new Redis(redisUrl, options);
      this.subClient = new Redis(redisUrl, options);

      this.setupEventHandlers(this.pubClient, 'Pub');
      this.setupEventHandlers(this.subClient, 'Sub');

      // Wait for both clients to be ready
      await Promise.all([
        this.waitForReady(this.pubClient),
        this.waitForReady(this.subClient),
      ]);

      this.adapterConstructor = createAdapter(this.pubClient, this.subClient);
      this.logger.log('Redis adapter connected successfully', 'connectToRedis');
    } catch (error) {
      this.logger.error('Failed to connect to Redis', error, 'connectToRedis');
      throw error;
    } finally {
      this.isConnecting = false;
    }
  }

  private waitForReady(client: Redis): Promise<void> {
    return new Promise((resolve, reject) => {
      if (client.status === 'ready') {
        resolve();
        return;
      }
      client.once('ready', () => resolve());
      client.once('error', (err) => reject(err));
    });
  }

  /**
   * Sets up event handlers for Redis client connection lifecycle events.
   */
  private setupEventHandlers(client: Redis, clientType: 'Pub' | 'Sub'): void {
    client.on('error', (err: Error) => {
      this.logger.error(
        `Redis ${clientType} Client Error: ${err.message}`,
        'setupEventHandlers',
      );
    });

    client.on('connect', () => {
      this.logger.log(
        `Redis ${clientType} Client connected`,
        'setupEventHandlers',
      );
    });

    client.on('ready', () => {
      this.logger.log(`Redis ${clientType} Client ready`, 'setupEventHandlers');
    });

    client.on('reconnecting', () => {
      this.logger.warn(
        `Redis ${clientType} Client reconnecting...`,
        'setupEventHandlers',
      );
    });

    client.on('close', () => {
      this.logger.warn(
        `Redis ${clientType} Client connection closed`,
        'setupEventHandlers',
      );
    });
  }

  createIOServer(port: number, options?: ServerOptions): any {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const server = super.createIOServer(port, options);
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call,@typescript-eslint/no-unsafe-member-access
    server.adapter(this.adapterConstructor);
    return server;
  }

  /**
   * Gracefully closes Redis connections.
   */
  async close(): Promise<void> {
    if (this.isClosed) {
      return;
    }

    this.isClosed = true;
    this.logger.log('Closing Redis connections...', 'close');

    try {
      await Promise.all([this.pubClient?.quit(), this.subClient?.quit()]);
      this.logger.log('Redis connections closed successfully', 'close');
    } catch (error) {
      this.logger.error('Error closing Redis connections', error, 'close');
      // Force disconnect if quit fails
      this.pubClient?.disconnect();
      this.subClient?.disconnect();
    }
  }
}
