import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { AuthService } from './auth.service';
import {
  AuthTokensResponseDto,
  LoginDto,
  LogoutResponseDto,
  RegisterDto,
  UserMeResponseDto,
} from './auth.dto';
import { JwtAuthGuard } from './jwt-auth.guard';
import { User } from './user.decorator';

/**
 * Auth controller. Exposes HTTP endpoints for registration, login, current user, and logout.
 * Protected routes require a valid Bearer access token (JwtAuthGuard).
 */
@ApiTags('Auth')
@Controller('api/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /**
   * Register a new user. Creates user and credential account, then returns user plus access and refresh tokens.
   * @param body - Validated register payload (email, name, password).
   * @returns `{ user, accessToken, refreshToken }`.
   * @throws ConflictException if email already exists.
   */
  @Post('register')
  @ApiOperation({
    summary: 'Register',
    description:
      'Register a new user. Creates user and credential account, returns user plus access and refresh tokens.',
  })
  @ApiBody({ type: RegisterDto })
  @ApiResponse({
    status: 201,
    description: 'User registered',
    type: AuthTokensResponseDto,
  })
  @ApiResponse({ status: 409, description: 'Email already exists' })
  async registerController(@Body() body: RegisterDto) {
    return this.authService.register(body);
  }

  /**
   * Log in with email and password. Returns user plus new access and refresh tokens.
   * @param body - Validated login payload (email, password).
   * @returns `{ user, accessToken, refreshToken }`.
   * @throws UnauthorizedException if user not found or password invalid.
   */
  @Post('login')
  @ApiOperation({
    summary: 'Login',
    description:
      'Log in with email and password. Returns user plus access and refresh tokens.',
  })
  @ApiBody({ type: LoginDto })
  @ApiResponse({
    status: 201,
    description: 'Login successful',
    type: AuthTokensResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Invalid email or password' })
  async loginController(@Body() body: LoginDto) {
    return this.authService.login(body);
  }

  /**
   * Get the current authenticated user and related data (sessions, accounts). Requires Bearer token.
   * @param user - Injected by JwtAuthGuard from token (userId).
   * @returns Full user with sessions and accounts (debug-friendly).
   * @throws NotFoundException if user no longer exists.
   */
  @Get('me')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiOperation({
    summary: 'Current user',
    description:
      'Get the current authenticated user with sessions and accounts. Requires Bearer token.',
  })
  @ApiResponse({
    status: 200,
    description: 'Current user with sessions and accounts',
    type: UserMeResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Missing or invalid token' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async meController(@User() user: { userId: string }) {
    return this.authService.me(user.userId);
  }

  /**
   * Log out: revokes all refresh sessions for the user and blacklists the current access token.
   * Requires Bearer token. After logout, that token cannot be used for API access.
   * @param user - Injected by JwtAuthGuard (userId).
   * @param req - Request; accessToken is set by JwtAuthGuard for blacklisting.
   * @returns `{ success: true }`.
   */
  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiOperation({
    summary: 'Logout',
    description:
      'Revoke all refresh sessions and blacklist the current access token. Requires Bearer token.',
  })
  @ApiResponse({
    status: 201,
    description: 'Logout successful',
    type: LogoutResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Missing or invalid token' })
  async logoutController(
    @User() user: { userId: string },
    @Req() req: { accessToken?: string },
  ) {
    return this.authService.logout(user.userId, req.accessToken);
  }
}
