import { Body, Controller, Get, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { type LoginDto, type RegisterDto } from './auth.dto';

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
  async meController() {
    return this.authService.me('');
  }

  @Post('logout')
  async logoutController() {
    return this.authService.logout('');
  }
}
