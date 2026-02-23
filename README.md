# sx Backend Application

## Local Setup & Installation

1. **Install dependencies:**
   ```bash
   $ pnpm install
   ```

2. **Environment Variables:**
   Create a `.env` file in the root directory and configure the following required variables:
   ```env
   DATABASE_URL="postgresql://user:password@host:port/database?sslmode=require&channel_binding=require"
   PORT=8080
   REDIS_URL="redis://localhost:6379"
   ```

3. **Database Setup:**
   Sync your database schema and generate the Prisma client:
   ```bash
   $ npx prisma db push
   $ npx prisma generate
   ```

## Running the application locally

```bash
# development
$ pnpm run start

# watch mode
$ pnpm run start:dev

# production mode
$ pnpm run start:prod
```

## Run tests

```bash
# unit tests
$ pnpm run test

# e2e tests
$ pnpm run test:e2e

# test coverage
$ pnpm run test:cov
```
