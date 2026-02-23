import { createParamDecorator, type ExecutionContext } from '@nestjs/common';

/**
 * Parameter decorator that returns the authenticated user from the request.
 * Use on protected routes (with JwtAuthGuard). Request.user is set by the guard from the JWT payload.
 * @returns `{ userId: string }` (subject from access token).
 */
export const User = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): { userId: string } => {
    const request = ctx
      .switchToHttp()
      .getRequest<{ user: { userId: string } }>();
    return request.user;
  },
);
