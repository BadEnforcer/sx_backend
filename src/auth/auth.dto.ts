import { z } from 'zod';
import { createZodDto } from 'nestjs-zod';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export const RegisterSchema = z.object({
  email: z.email(),
  name: z.string().min(1),
  password: z.string(),
  // .regex(
  //   /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
  // ),
});

export const LoginSchema = z.object({
  email: z.email(),
  password: z.string(),
});

export class RegisterDto extends createZodDto(RegisterSchema) {}

export class LoginDto extends createZodDto(LoginSchema) {}

/** User shape returned in register/login token responses. */
export class AuthUserDto {
  @ApiProperty({ example: 'uuid' })
  id!: string;

  @ApiProperty({ example: 'Jane Doe' })
  name!: string;

  @ApiProperty({ example: 'jane@example.com' })
  email!: string;

  @ApiProperty({ example: false })
  emailVerified!: boolean;

  @ApiPropertyOptional({ example: 'https://example.com/avatar.png' })
  image?: string | null;

  @ApiProperty()
  createdAt!: Date;

  @ApiProperty()
  updatedAt!: Date;
}

/** Response for POST /auth/register and POST /auth/login. */
export class AuthTokensResponseDto {
  @ApiProperty({
    type: () => AuthUserDto,
    description: 'Registered or logged-in user',
  })
  user!: AuthUserDto;

  @ApiProperty({ description: 'JWT access token (Bearer)' })
  accessToken!: string;

  @ApiProperty({ description: 'Refresh token for obtaining new access tokens' })
  refreshToken!: string;
}

/** Session record (debug). */
export class SessionDto {
  @ApiProperty()
  id!: string;

  @ApiProperty()
  expiresAt!: Date;

  @ApiProperty()
  token!: string;

  @ApiProperty()
  createdAt!: Date;

  @ApiProperty()
  updatedAt!: Date;

  @ApiPropertyOptional()
  ipAddress!: string | null;

  @ApiPropertyOptional()
  userAgent!: string | null;

  @ApiProperty()
  userId!: string;
}

/** Account record (debug). */
export class AccountDto {
  @ApiProperty()
  id!: string;

  @ApiProperty()
  accountId!: string;

  @ApiProperty({ example: 'credential' })
  providerId!: string;

  @ApiProperty()
  userId!: string;

  @ApiPropertyOptional()
  accessToken!: string | null;

  @ApiPropertyOptional()
  refreshToken!: string | null;

  @ApiPropertyOptional()
  idToken!: string | null;

  @ApiPropertyOptional()
  accessTokenExpiresAt!: Date | null;

  @ApiPropertyOptional()
  refreshTokenExpiresAt!: Date | null;

  @ApiPropertyOptional()
  scope!: string | null;

  @ApiProperty()
  createdAt!: Date;

  @ApiProperty()
  updatedAt!: Date;
}

/** Response for GET /auth/me (user with sessions and accounts). */
export class UserMeResponseDto extends AuthUserDto {
  @ApiProperty({ type: [SessionDto] })
  sessions!: SessionDto[];

  @ApiProperty({ type: [AccountDto] })
  accounts!: AccountDto[];
}

/** Response for POST /auth/logout. */
export class LogoutResponseDto {
  @ApiProperty({ example: true, description: 'Logout completed' })
  success!: boolean;
}
