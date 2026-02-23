import {
  ConflictException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { REDIS_CLIENT } from '../redis/redis.constants';
import type { RegisterDto, LoginDto } from './auth.dto';
import * as bcrypt from 'bcrypt';
import * as jose from 'jose';
import * as crypto from 'node:crypto';
import type { Redis } from 'ioredis';

const JWKS_PUBLIC_KEY_CACHE_KEY = 'jwks:publicKey';
const JWKS_PUBLIC_KEY_TTL_SEC = 30;

const JWKS_RESPONSE_CACHE_KEY = 'jwks:response';
const JWKS_RESPONSE_TTL_SEC = 300; // 5 minutes
const JWKS_PRIVATE_KEY_CACHE_KEY = 'jwks:privateKey';
const JWKS_PRIVATE_KEY_TTL_SEC = 300; // 5 minutes

const ACCESS_TOKEN_TTL_MIN_DEFAULT = 15;
const ACCESS_TOKEN_TTL_MAX = 30;
const REFRESH_TOKEN_DAYS_MIN = 7;
const REFRESH_TOKEN_DAYS_MAX = 30;
const REFRESH_TOKEN_DAYS_DEFAULT = 7;

/**
 * Auth service. Handles registration, login, logout, token issuance/verification, and JWKS.
 * Uses Prisma for user/session/account/JWKS storage and Redis for public-key cache and access-token blacklist.
 */
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    @Inject(REDIS_CLIENT) private readonly redis: Redis,
  ) {}

  /**
   * Register a new user. Creates user and credential account in a transaction, then issues access and refresh tokens.
   * @param body - Validated register payload (email, name, password).
   * @returns `{ user, accessToken, refreshToken }` (refreshToken includes expiresAt).
   * @throws ConflictException if email already exists.
   */
  async register(body: RegisterDto) {
    this.logger.log(`Registering user ${body.email}`);

    const newUser = await this.prisma.$transaction(async (tx) => {
      const existingUser = await tx.user.findUnique({
        where: { email: body.email },
      });

      if (existingUser) {
        this.logger.error(`User ${body.email} already exists`);
        throw new ConflictException('User already exists');
      }

      const hashedPassword = await bcrypt.hash(body.password, 10);
      const userId = crypto.randomUUID();
      const name = body.name;

      const user = await tx.user.create({
        data: {
          id: userId,
          name,
          email: body.email,
          emailVerified: false,
        },
      });

      await tx.account.create({
        data: {
          id: crypto.randomUUID(),
          accountId: userId,
          providerId: 'credential',
          userId,
          password: hashedPassword,
        },
      });

      return user;
    });

    this.logger.log(`User registered successfully: ${newUser.email}`);
    this.logger.log('Generating access token');
    const accessToken = await this.signAccessToken(newUser.id);
    this.logger.log('Generating refresh token');
    const refreshToken = await this.generateRefreshToken(newUser.id);
    this.logger.log('Returning user');
    return { user: newUser, accessToken, refreshToken };
  }

  /**
   * Log in with email and password. Looks up user and credential account in a transaction, verifies password, then issues new tokens.
   * @param body - Validated login payload (email, password).
   * @returns `{ user, accessToken, refreshToken }`.
   * @throws UnauthorizedException if user not found, no credential account, or password invalid.
   */
  async login(body: LoginDto) {
    this.logger.log(`Login attempt for ${body.email}`);

    const user = await this.prisma.$transaction(async (tx) => {
      const existingUser = await tx.user.findUnique({
        where: { email: body.email },
        include: {
          accounts: {
            where: { providerId: 'credential' },
            take: 1,
          },
        },
      });

      if (!existingUser) {
        this.logger.error(`Login failed: user not found ${body.email}`);
        throw new UnauthorizedException('Invalid email or password');
      }

      const credentialAccount = existingUser.accounts[0];
      if (!credentialAccount?.password) {
        this.logger.error(
          `Login failed: no credential account for ${body.email}`,
        );
        throw new UnauthorizedException('Invalid email or password');
      }

      const passwordValid = await bcrypt.compare(
        body.password,
        credentialAccount.password,
      );
      if (!passwordValid) {
        this.logger.error(`Login failed: invalid password for ${body.email}`);
        throw new UnauthorizedException('Invalid email or password');
      }

      return {
        id: existingUser.id,
        name: existingUser.name,
        email: existingUser.email,
        emailVerified: existingUser.emailVerified,
        image: existingUser.image,
        createdAt: existingUser.createdAt,
        updatedAt: existingUser.updatedAt,
      };
    });

    this.logger.log(`User logged in successfully: ${user.email}`);
    this.logger.log('Generating access token');
    const accessToken = await this.signAccessToken(user.id);
    this.logger.log('Generating refresh token');
    const refreshToken = await this.generateRefreshToken(user.id);
    this.logger.log('Returning user');
    return { user, accessToken, refreshToken };
  }

  /**
   * Fetch the current user by id with sessions and accounts (for debug). Does not validate tokens.
   * @param userId - User id (e.g. from JWT sub).
   * @returns User with sessions and accounts.
   * @throws NotFoundException if user not found.
   */
  async me(userId: string) {
    this.logger.log(`Me requested for userId=${userId}`);

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        sessions: true,
        accounts: true,
      },
    });

    if (!user) {
      this.logger.error(`Me failed: user not found userId=${userId}`);
      throw new NotFoundException('User not found');
    }

    this.logger.log(`Returning user and session info for ${user.email}`);
    return user;
  }

  /**
   * Log out: delete all sessions for the user (revoke refresh tokens) and optionally blacklist the current access token in Redis.
   * @param userId - User id to revoke sessions for.
   * @param accessToken - Optional current access token to blacklist (prevents further API use until it expires).
   * @returns `{ success: true }`.
   */
  async logout(userId: string, accessToken?: string) {
    this.logger.log(`Logout for userId=${userId}`);

    await this.prisma.$transaction(async (tx) => {
      await tx.session.deleteMany({
        where: { userId },
      });
    });
    this.logger.log(`Revoked all refresh sessions for userId=${userId}`);

    if (accessToken) {
      await this.blacklistAccessToken(accessToken);
      this.logger.log(`Blacklisted access token for userId=${userId}`);
    }

    return { success: true };
  }

  /**
   * Verifies the access token: loads public key (cached in Redis), checks signature and expiry, returns subject.
   * @param token - JWT access token string.
   * @returns `{ sub: string }` (userId).
   * @throws If token invalid, expired, or missing sub.
   */
  async verifyAccessToken(token: string): Promise<{ sub: string }> {
    const publicKeyPem = await this.getPublicKey();
    const publicKey = await jose.importSPKI(publicKeyPem, 'RS256');
    const { payload } = await jose.jwtVerify(token, publicKey);
    const sub = payload.sub;
    if (typeof sub !== 'string') throw new Error('Invalid token: missing sub');
    return { sub };
  }

  /** Redis key for access-token blacklist: `jwt:blacklist:<sha256(token)>`. */
  private getAccessTokenBlacklistKey(token: string): string {
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    return `jwt:blacklist:${hash}`;
  }

  /**
   * Check whether the access token has been blacklisted (e.g. after logout).
   * @param token - JWT access token string.
   * @returns true if the token is blacklisted.
   */
  async isAccessTokenBlacklisted(token: string): Promise<boolean> {
    const key = this.getAccessTokenBlacklistKey(token);
    const exists = await this.redis.exists(key);
    return exists === 1;
  }

  /**
   * Blacklist an access token in Redis so it can no longer be used. TTL is until token exp, or default access TTL if exp missing.
   * @param token - JWT access token string to blacklist.
   */
  async blacklistAccessToken(token: string): Promise<void> {
    const payload = jose.decodeJwt(token);
    const exp = payload.exp;
    const nowSeconds = Math.floor(Date.now() / 1000);
    let ttlSeconds = ACCESS_TOKEN_TTL_MIN_DEFAULT * 60;

    if (typeof exp === 'number') {
      ttlSeconds = Math.max(0, exp - nowSeconds);
      if (ttlSeconds === 0) {
        return;
      }
    }

    const key = this.getAccessTokenBlacklistKey(token);
    await this.redis.set(key, '1', 'EX', ttlSeconds);
  }

  /**
   * Return the public keys as a JSON Web Key Set for frontend JWT verification.
   * Includes all currently valid JWKS keys (not expired). Each key has kid, alg, use.
   * Note: The response is cached in Redis for 5 minutes to prevent DoS via expensive crypto operations.
   */
  async getJwks(): Promise<{ keys: jose.JWK[] }> {
    const cached = await this.redis.get(JWKS_RESPONSE_CACHE_KEY);
    if (cached) {
      return JSON.parse(cached) as { keys: jose.JWK[] };
    }

    const now = new Date();
    const rows = await this.prisma.jwks.findMany({
      where: { OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] },
    });
    const keys: jose.JWK[] = [];
    for (const row of rows) {
      const publicKey = await jose.importSPKI(row.publicKey, 'RS256');
      const jwk = await jose.exportJWK(publicKey);
      keys.push({
        ...jwk,
        kid: row.id,
        alg: 'RS256',
        use: 'sig',
      } as jose.JWK);
    }

    const response = { keys };
    await this.redis.set(
      JWKS_RESPONSE_CACHE_KEY,
      JSON.stringify(response),
      'EX',
      JWKS_RESPONSE_TTL_SEC,
    );
    return response;
  }

  /** Get JWKS public key PEM: from Redis cache if present, else from DB and then cached (30s TTL). */
  private async getPublicKey(): Promise<string> {
    const cached = await this.redis.get(JWKS_PUBLIC_KEY_CACHE_KEY);
    if (cached) return cached;

    const now = new Date();
    const existing = await this.prisma.jwks.findFirst({
      where: { OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] },
    });
    if (!existing) throw new Error('No JWKS key available for verification');

    await this.redis.set(
      JWKS_PUBLIC_KEY_CACHE_KEY,
      existing.publicKey,
      'EX',
      JWKS_PUBLIC_KEY_TTL_SEC,
    );
    return existing.publicKey;
  }

  /** Get current JWKS private key: reuse from DB if a valid key exists, otherwise generate and store a new RSA key pair. Returns kid for JWT header. */
  private async getOrCreateJwksKey(): Promise<{
    privateKeyPem: string;
    kid: string;
  }> {
    const cached = await this.redis.get(JWKS_PRIVATE_KEY_CACHE_KEY);
    if (cached) {
      this.logger.debug(`Reusing cached JWKS private key`);
      return JSON.parse(cached) as { privateKeyPem: string; kid: string };
    }

    const now = new Date();
    const existing = await this.prisma.jwks.findFirst({
      where: { OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] },
    });
    if (existing) {
      this.logger.debug(`Reusing existing JWKS key id=${existing.id}`);
      const result = { privateKeyPem: existing.privateKey, kid: existing.id };
      await this.redis.set(
        JWKS_PRIVATE_KEY_CACHE_KEY,
        JSON.stringify(result),
        'EX',
        JWKS_PRIVATE_KEY_TTL_SEC,
      );
      return result;
    }

    this.logger.log('Creating new JWKS key pair');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    const jwksId = crypto.randomUUID();
    await this.prisma.jwks.create({
      data: {
        id: jwksId,
        publicKey: publicKey,
        privateKey: privateKey,
        createdAt: now,
        expiresAt: null,
      },
    });
    this.logger.log(`JWKS key created id=${jwksId}`);

    // Break caches when a new key is added
    await this.redis.del(JWKS_RESPONSE_CACHE_KEY);
    await this.redis.del(JWKS_PUBLIC_KEY_CACHE_KEY);

    const result = { privateKeyPem: privateKey, kid: jwksId };
    await this.redis.set(
      JWKS_PRIVATE_KEY_CACHE_KEY,
      JSON.stringify(result),
      'EX',
      JWKS_PRIVATE_KEY_TTL_SEC,
    );
    return result;
  }

  /** Access token TTL in minutes from config, clamped to 15–30. Returns string like "15m" for jose. */
  private getAccessTokenTtl(): string {
    const minutes = this.config.get<number>(
      'ACCESS_TOKEN_TTL_MINUTES',
      ACCESS_TOKEN_TTL_MIN_DEFAULT,
    );
    const clamped = Math.min(
      ACCESS_TOKEN_TTL_MAX,
      Math.max(ACCESS_TOKEN_TTL_MIN_DEFAULT, minutes),
    );
    return `${clamped}m`;
  }

  /** Refresh token lifetime in days from config, clamped to 7–30. */
  private getRefreshTokenDays(): number {
    const days = this.config.get<number>(
      'REFRESH_TOKEN_TTL_DAYS',
      REFRESH_TOKEN_DAYS_DEFAULT,
    );
    return Math.min(
      REFRESH_TOKEN_DAYS_MAX,
      Math.max(REFRESH_TOKEN_DAYS_MIN, days),
    );
  }

  /** Issue a new RS256 access token for the given user id with configured TTL. Header includes kid for JWKS lookup. */
  private async signAccessToken(userId: string): Promise<string> {
    this.logger.debug(`Signing access token for userId=${userId}`);
    const { privateKeyPem, kid } = await this.getOrCreateJwksKey();
    const privateKey = await jose.importPKCS8(privateKeyPem, 'RS256');
    const ttl = this.getAccessTokenTtl();
    return await new jose.SignJWT({})
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid })
      .setSubject(userId)
      .setIssuedAt()
      .setExpirationTime(ttl)
      .sign(privateKey);
  }

  /**
   * Create a new refresh token: random value, stored as a Session row with configured expiry. Optional ipAddress/userAgent.
   * @param userId - User id to attach the session to.
   * @param opts - Optional ipAddress and userAgent for the session.
   * @returns `{ refreshToken, expiresAt }`.
   */
  private async generateRefreshToken(
    userId: string,
    opts?: { ipAddress?: string; userAgent?: string },
  ): Promise<{ refreshToken: string; expiresAt: Date }> {
    this.logger.debug(`Generating refresh token for userId=${userId}`);
    const refreshToken = crypto.randomBytes(32).toString('base64url');
    const days = this.getRefreshTokenDays();
    const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
    await this.prisma.session.create({
      data: {
        id: crypto.randomUUID(),
        token: refreshToken,
        userId,
        expiresAt,
        ipAddress: opts?.ipAddress ?? null,
        userAgent: opts?.userAgent ?? null,
      },
    });
    this.logger.debug(
      `Refresh token created for userId=${userId}, expiresAt=${expiresAt.toISOString()}`,
    );
    return { refreshToken, expiresAt };
  }
}
