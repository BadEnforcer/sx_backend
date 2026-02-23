import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ThrottlerModule } from '@nestjs/throttler';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ThrottlerStorageRedisService } from '@nest-lab/throttler-storage-redis';
import { Request } from 'express';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module';
import { APP_PIPE } from '@nestjs/core';
import { ZodValidationPipe } from 'nestjs-zod';
import { RedisModule } from './redis/redis.module';

@Module({
  imports: [
    RedisModule,
    PrismaModule,
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        throttlers: [
          {
            ttl: 60, // 1 minute
            limit: 10, // 10 requests per minute
            skipIf(context): boolean {
              const req = context.switchToHttp().getRequest<Request>();
              // key 'whitelisted_ips' is a comma-separated list of IP addresses
              const ipString = config.get<string>('WHITELISTED_IPS') ?? '';
              if (!ipString) {
                return false; // do not skip rate limiting
              }

              const whitelistedIpsList: string[] = ipString
                .split(',')
                .map((ip: string) => ip.trim());
              const ip = req.ip;
              if (whitelistedIpsList.includes(ip ?? '')) {
                return true; // skip rate limiting
              }

              return true;
            },
          },
        ],
        storage: new ThrottlerStorageRedisService(),
      }),
    }),
    AuthModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_PIPE,
      useClass: ZodValidationPipe,
    },
  ],
})
export class AppModule {}
