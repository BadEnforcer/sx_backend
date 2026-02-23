# ===============================
# Stage 1: Build
# ===============================
FROM node:22-alpine AS builder

# Install pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate
RUN pnpm config set ignore-scripts false

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./
COPY pnpm-lock.yaml ./

# Install all dependencies (including dev dependencies for build)
RUN pnpm install --no-frozen-lockfile

# Copy Prisma schema and generate client
COPY prisma ./prisma/
RUN npx prisma generate

# Copy source code
COPY . .

# Build the application
RUN NODE_OPTIONS="--max-old-space-size=4096" pnpm run build

# ===============================
# Stage 2: Production
# ===============================
FROM node:22-alpine AS production

# Install pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate
RUN pnpm config set ignore-scripts false

# Set working directory
WORKDIR /app

# Set environment to production
ENV NODE_ENV=production

# Copy package files
COPY package*.json ./
COPY pnpm-lock.yaml ./

# Install only production dependencies
RUN pnpm install --no-frozen-lockfile --prod

# Copy Prisma schema and generate client from it
COPY --from=builder /app/prisma ./prisma/
RUN npx prisma generate

# Copy built application from builder stage
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/tsconfig.paths.json ./tsconfig.paths.json

# Copy firebase credentials
RUN mkdir -p ./src
COPY --from=builder /app/src/firebase.json ./src/firebase.json

# Expose port
EXPOSE 8080

# Start the application
CMD ["npm", "run", "start:prod"]
