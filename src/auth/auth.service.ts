import { ConflictException, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from 'src/prisma/prisma.service';
import type { RegisterDto, LoginDto } from './auth.dto';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import * as jose from 'jose';
import * as crypto from 'node:crypto';

const ACCESS_TOKEN_TTL_MIN_DEFAULT = 15;
const ACCESS_TOKEN_TTL_MAX = 30;
const REFRESH_TOKEN_DAYS_MIN = 7;
const REFRESH_TOKEN_DAYS_MAX = 30;
const REFRESH_TOKEN_DAYS_DEFAULT = 7;

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

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
      const userId = uuidv4();
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
          id: uuidv4(),
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

  async login(body: LoginDto) {
    this.logger.log(`Login attempt for ${body.email}`, body);
    return true;
  }

  async me(userId: string) {
    this.logger.log(`Me requested for userId=${userId}`);
    return true;
  }

  async logout(userId: string) {
    this.logger.log(`Logout for userId=${userId}`);
    return true;
  }

  private async getOrCreateJwksKey(): Promise<{ privateKeyPem: string }> {
    const now = new Date();
    const existing = await this.prisma.jwks.findFirst({
      where: { OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] },
    });
    if (existing) {
      this.logger.debug(`Reusing existing JWKS key id=${existing.id}`);
      return { privateKeyPem: existing.privateKey };
    }

    this.logger.log('Creating new JWKS key pair');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    const jwksId = uuidv4();
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
    return { privateKeyPem: privateKey };
  }

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

  private async signAccessToken(userId: string): Promise<string> {
    this.logger.debug(`Signing access token for userId=${userId}`);
    const { privateKeyPem } = await this.getOrCreateJwksKey();
    const privateKey = await jose.importPKCS8(privateKeyPem, 'RS256');
    const ttl = this.getAccessTokenTtl();
    return await new jose.SignJWT({})
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
      .setSubject(userId)
      .setIssuedAt()
      .setExpirationTime(ttl)
      .sign(privateKey);
  }

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
        id: uuidv4(),
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
