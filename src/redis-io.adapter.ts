import { IoAdapter } from '@nestjs/platform-socket.io';
import { ServerOptions } from 'socket.io';
import { createAdapter } from '@socket.io/redis-adapter';
import { createClient } from 'redis';
import { Logger } from '@nestjs/common';

export class RedisIoAdapter extends IoAdapter {
  private readonly logger = new Logger(RedisIoAdapter.name);

  createIOServer(port: number, options?: ServerOptions): any {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const server = super.createIOServer(port, options);
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    server.adapter(this.adapterConstructor);
    return server;
  }

  async close(): Promise<void> {
    const pubPromise =
      this.pubClient && this.pubClient.isOpen ? this.pubClient.quit() : null;
    const subPromise =
      this.subClient && this.subClient.isOpen ? this.subClient.quit() : null;

    if (pubPromise || subPromise) {
      await Promise.all([pubPromise, subPromise]);
      this.logger.log('Redis adapter disconnected', 'close');
    }
  }

  private pubClient!: ReturnType<typeof createClient>;
  private subClient!: ReturnType<typeof createClient>;
  private adapterConstructor?: ReturnType<typeof createAdapter>;

  async connectToRedis(): Promise<void> {
    this.pubClient = createClient({
      url: process.env.REDIS_URL,
      socket: {
        keepAlive: true,
        connectTimeout: 10000,
      },
    });

    this.subClient = this.pubClient.duplicate();

    this.pubClient.on('error', (err) =>
      this.logger.error('Redis Pub Client Error', err, 'connectToRedis'),
    );
    this.subClient.on('error', (err) =>
      this.logger.error('Redis Sub Client Error', err, 'connectToRedis'),
    );

    await Promise.all([this.pubClient.connect(), this.subClient.connect()]);

    this.adapterConstructor = createAdapter(this.pubClient, this.subClient);
    this.logger.log('Redis adapter connected', 'connectToRedis');
  }
}
