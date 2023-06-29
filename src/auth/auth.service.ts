import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async signupLocal(dto: AuthDto): Promise<Tokens> {
    const hashedPassword = this.hashedData(dto.password);

    const newUser = await this.prisma.user.create({
      data: {
        email: dto.email,
        hashedPassword,
        name: dto.name,
      },
    });

    const tokens = await this.getTokens(newUser.id, newUser.email);
    await this.updateRefreshToken(newUser.id, tokens.refreshToken);

    return tokens;
  }

  async loginLocal({ email, password }: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: email,
      },
    });

    if (!user)
      throw new ForbiddenException('Access Denied!. This user does not exist');

    const isPasswordValid = await bcrypt.compare(password, user.hashedPassword);

    if (!isPasswordValid)
      throw new ForbiddenException(
        'Access Denied. You entered a wrong password',
      );

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refreshToken);

    return tokens;
  }

  logout() {}

  refreshTokens() {}

  async updateRefreshToken(userId: number, refreshToken: string) {
    const hash = await this.hashedData(refreshToken);

    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRefreshToken: hash,
      },
    });
  }

  hashedData(password: string) {
    return bcrypt.hashSync(password, 10);
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        { sub: userId, email },
        {
          secret: 'at-secret',
          expiresIn: 60 * 15,
        },
      ),
      this.jwtService.signAsync(
        { sub: userId, email },
        {
          secret: 'rt-secret',
          expiresIn: 60 * 60 * 24 * 7,
        },
      ),
    ]);

    return {
      accessToken: at,
      refreshToken: rt,
    };
  }
}
