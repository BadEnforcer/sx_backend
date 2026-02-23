import { Injectable, OnModuleInit, Logger } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { Pool } from 'pg';

/** Context passed to Prisma $allOperations extension (typed to avoid strict generics inferring `never`) */
interface AllOperationsContext {
  operation: string;
  model: string | undefined;
  args: unknown;
  query: (args: unknown) => Promise<unknown>;
}

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger(PrismaService.name);

  constructor() {
    const connectionString = process.env.DATABASE_URL;
    if (!connectionString) {
      throw new Error('DATABASE_URL is not set');
    }
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call
    const pool = new Pool({ connectionString });
    const adapter = new PrismaPg(pool);

    super({
      adapter,
      transactionOptions: {
        timeout: 30000, // 30 seconds
      },
    });

    const logger = this.logger;
    const client = this.$extends({
      query: {
        $allModels: {
          async $allOperations({
            operation,
            model,
            args,
            query,
          }: AllOperationsContext) {
            const start = performance.now();
            const result = await query(args);
            const end = performance.now();
            const duration = (end - start).toFixed(2);

            if (model) {
              logger.log(`DB ${model}.${operation} took ${duration}ms`);
            }

            // Prisma's DynamicQueryExtensionCb infers never when generics are complex; result is the query return
            return result as never;
          },
        },
      },
    });

    // Constructor returns extended client so the injected service is the extended instance
    return client as unknown as PrismaService;
  }

  async onModuleInit() {
    await this.$connect();
  }
}
