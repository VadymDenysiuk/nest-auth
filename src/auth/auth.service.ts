import { ConflictException, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { LoginDto, RegisterDto } from './dto';
import { UserService } from 'src/user/user.service';
import { Tokens } from './interfaces';
import { compareSync } from 'bcrypt';
import { Token, User } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { v4 } from 'uuid';
import { add } from 'date-fns';

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name);
    constructor(
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
        private readonly prismaServide: PrismaService,
    ) {}

    async refreshTokens(refreshToken: string, agent: string): Promise<Tokens> {
        const token = await this.prismaServide.token.findUnique({ where: { token: refreshToken } });

        if (!token) throw new UnauthorizedException();

        await this.prismaServide.token.delete({ where: { token: refreshToken } });
        if (new Date(token.exp) < new Date()) {
            throw new UnauthorizedException();
        }

        const user = await this.userService.findOne(token.userId);

        return this.generateTokens(user, agent);
    }

    async register(dto: RegisterDto) {
        const user: User = await this.userService.findOne(dto.email).catch((err) => {
            this.logger.error(err);
            return null;
        });

        if (user) {
            throw new ConflictException('User with this email already exist');
        }

        return this.userService.save(dto).catch((err) => {
            this.logger.error(err);
            return null;
        });
    }

    async login(dto: LoginDto, agent: string): Promise<Tokens> {
        const user: User = await this.userService.findOne(dto.email, true).catch((err) => {
            this.logger.error(err);
            return null;
        });

        if (!user || !compareSync(dto.password, user.password)) {
            throw new UnauthorizedException('Wrong login or password');
        }

        return this.generateTokens(user, agent);
    }

    private async generateTokens(user: User, agent: string): Promise<Tokens> {
        const accessToken = `Bearer ${this.jwtService.sign({
            id: user.id,
            email: user.email,
            roles: user.roles,
        })}`;

        const refreshToken = await this.getRefreshToken(user.id, agent);

        return { accessToken, refreshToken };
    }

    private async getRefreshToken(userId: string, agent: string): Promise<Token> {
        const token = await this.prismaServide.token.findFirst({
            where: { userId, userAgent: agent },
        });

        return this.prismaServide.token.upsert({
            where: { token: token?.token ?? '' },
            update: { token: v4(), exp: add(new Date(), { months: 1 }) },
            create: { token: v4(), exp: add(new Date(), { months: 1 }), userId, userAgent: agent },
        });
    }

    deleteRefreshToken(token: string) {
        return this.prismaServide.token.delete({ where: { token } });
    }
}
