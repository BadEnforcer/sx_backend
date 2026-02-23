import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import { AppModule } from './app.module';
import {
  SwaggerModule,
  DocumentBuilder,
  type OpenAPIObject,
} from '@nestjs/swagger';
import { cleanupOpenApiDoc } from 'nestjs-zod';
import { RedisIoAdapter } from './redis-io.adapter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
        },
      },
      crossOriginResourcePolicy: { policy: 'cross-origin' },
    }),
  );
  app.enableCors({ origin: '*' });

  const config = new DocumentBuilder()
    .setTitle('Swagger API')
    .setDescription('Backend API Documentation')
    .setVersion('2.0.0')
    .addCookieAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);

  const openApiDoc: OpenAPIObject = cleanupOpenApiDoc(document);
  SwaggerModule.setup('api', app, openApiDoc, {
    jsonDocumentUrl: '/json',
  });

  let redisIoAdapter: RedisIoAdapter | null = null;

  if (!process.env.REDIS_URL) {
    throw new Error('REDIS_URL is not set');
  }

  redisIoAdapter = new RedisIoAdapter(app);
  await Promise.race([
    redisIoAdapter.connectToRedis(),
    new Promise<never>((_, reject) =>
      setTimeout(
        () => reject(new Error('Redis connection timeout (15s)')),
        15_000,
      ),
    ),
  ]);

  await app.listen(process.env.PORT ?? 3000);
}
void bootstrap();
