import { Injectable, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private authService: AuthService) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    
    // Extract token from Authorization header
    const authHeader = request.headers.authorization;
    if (!authHeader) {
      throw new UnauthorizedException('No authorization header provided');
    }

    const token = authHeader.replace('Bearer ', '');
    if (!token) {
      throw new UnauthorizedException('No token provided');
    }

    try {
      // First try to validate as Supabase JWT (from frontend)
      const user = await this.authService.validateSupabaseJWT(token);
      request.user = user;
      return true;
    } catch (supabaseError) {
      // Fallback to standard JWT validation
      try {
        return await super.canActivate(context) as boolean;
      } catch (jwtError) {
        throw new UnauthorizedException('Invalid authentication token');
      }
    }
  }
}