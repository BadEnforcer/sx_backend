import {
  type CanActivate,
  type ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from './auth.service';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<{
      headers: { authorization?: string };
      user?: { userId: string };
    }>();
    const authHeader = request.headers?.authorization;
    const token = this.extractBearerToken(authHeader);

    if (!token) {
      throw new UnauthorizedException(
        'Missing or invalid Authorization header',
      );
    }

    try {
      const payload = await this.authService.verifyAccessToken(token);
      request.user = { userId: payload.sub };
      return true;
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  private extractBearerToken(authHeader: string | undefined): string | null {
    if (!authHeader || typeof authHeader !== 'string') return null;
    const [scheme, token] = authHeader.split(/\s+/);
    if (scheme?.toLowerCase() !== 'bearer' || !token) return null;
    return token;
  }
}
