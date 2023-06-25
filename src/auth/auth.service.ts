import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  hashedData(password: string) {
    return bcrypt.hashSync(password, 10);
  }

  signupLocal(dto: AuthDto): Promise<Tokens> {
    const hashedPassword = this.hashedData(dto.password);

    const newUser = this.prisma.user.create({
      data: {
        email: dto.email,
        hashedPassword,
      },
    });
  }

  loginLocal() {}

  logout() {}

  refreshTokens() {}
}
