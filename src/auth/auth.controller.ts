import { Controller, Get, Post } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('api/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async registerController() {
    return this.authService.register();
  }

  @Post('login')
  async loginController() {
    return this.authService.login();
  }

  @Get('me')
  async meController() {
    return this.authService.me();
  }

  @Post('logout')
  async logoutController() {
    return this.authService.logout();
  }
}
