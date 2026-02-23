import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto } from './auth.dto';
import { JwtAuthGuard } from './jwt-auth.guard';
import { User } from './user.decorator';

@Controller('api/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async registerController(@Body() body: RegisterDto) {
    return this.authService.register(body);
  }

  @Post('login')
  async loginController(@Body() body: LoginDto) {
    return this.authService.login(body);
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  async meController(@User() user: { userId: string }) {
    return this.authService.me(user.userId);
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  async logoutController(
    @User() user: { userId: string },
    @Req() req: { accessToken?: string },
  ) {
    return this.authService.logout(user.userId, req.accessToken);
  }
}
