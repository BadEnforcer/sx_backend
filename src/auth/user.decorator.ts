import { createParamDecorator, type ExecutionContext } from '@nestjs/common';

// returns user when it's parsed from the request
export const User = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): { userId: string } => {
    const request = ctx
      .switchToHttp()
      .getRequest<{ user: { userId: string } }>();
    return request.user;
  },
);
