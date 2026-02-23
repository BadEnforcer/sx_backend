import { Global, Module, OnApplicationShutdown, Inject } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Redis } from 'ioredis';
import { REDIS_CLIENT } from './redis.constants';

// Define the provider for the Redis client
const redisProvider = {
  // Use the constant as the injection token
  provide: REDIS_CLIENT,

  // Use a factory to create the client
  useFactory: (configService: ConfigService) => {
    // Get the connection URL from the .env file
    const redisUrl = configService.get<string>('REDIS_URL');
    if (!redisUrl) {
      throw new Error('REDIS_URL is not defined in your .env file');
    }

    // Create and return the client instance
    return new Redis(redisUrl);
  },

  // Inject ConfigService to use it in the factory
  inject: [ConfigService],
};

@Global() // <-- This makes the module global
@Module({
  // Import ConfigModule so we can use ConfigService in the factory
  imports: [ConfigModule],

  // Add the provider
  providers: [redisProvider],

  // Export the provider so it's available for injection
  exports: [redisProvider],
})
export class RedisModule implements OnApplicationShutdown {
  constructor(@Inject(REDIS_CLIENT) private readonly redisClient: Redis) {}

  // Gracefully disconnect on app shutdown
  async onApplicationShutdown() {
    await this.redisClient.quit();
    console.log('Disconnected from Redis');
  }
}
