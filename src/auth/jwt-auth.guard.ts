import {
  type CanActivate,
  type ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from './auth.service';

/**
 * Guard that validates the Bearer access token and attaches the user to the request.
 * Rejects blacklisted tokens, verifies signature and expiry via JWKS, then sets request.user and request.accessToken.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  /**
   * Extracts Bearer token from Authorization header, checks blacklist, verifies JWT, and sets request.user and request.accessToken.
   * @throws UnauthorizedException if header missing, token blacklisted, or token invalid/expired.
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<{
      headers: { authorization?: string };
      user?: { userId: string };
      accessToken?: string;
    }>();
    const authHeader = request.headers?.authorization;
    const token = this.extractBearerToken(authHeader);

    if (!token) {
      throw new UnauthorizedException(
        'Missing or invalid Authorization header',
      );
    }

    try {
      const isBlacklisted =
        await this.authService.isAccessTokenBlacklisted(token);
      if (isBlacklisted) {
        throw new UnauthorizedException('Invalid or expired token');
      }

      const payload = await this.authService.verifyAccessToken(token);
      request.user = { userId: payload.sub };
      request.accessToken = token;
      return true;
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  /** Parses "Bearer <token>" from the Authorization header; returns null if missing or malformed. */
  private extractBearerToken(authHeader: string | undefined): string | null {
    if (!authHeader || typeof authHeader !== 'string') return null;
    const [scheme, token] = authHeader.split(/\s+/);
    if (scheme?.toLowerCase() !== 'bearer' || !token) return null;
    return token;
  }
}
