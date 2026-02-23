import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(private readonly prisma: PrismaService) {}

  async register() {
    return true;
  }

  async login() {
    return true;
  }

  async me() {
    return true;
  }

  async logout() {
    return true;
  }
}
