import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { DatabaseService } from '../database/database.service';

export interface JwtPayload {
  sub: string; // user id
  email: string;
  organizationId: string;
  role: string;
  iat?: number;
  exp?: number;
}

export interface UserContext {
  id: string;
  email: string;
  organizationId: string;
  role: string;
  permissions: string[];
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private jwtService: JwtService,
    private databaseService: DatabaseService,
  ) {}

  async validateJwtPayload(payload: JwtPayload): Promise<UserContext> {
    try {
      // Query user profile with organization info
      const user = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('user_profiles')
          .select(`
            id,
            email,
            full_name,
            role,
            permissions,
            organization_id,
            organizations!inner(id, name, tier)
          `)
          .eq('id', payload.sub)
          .single();
      });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      return {
        id: user.id,
        email: user.email,
        organizationId: user.organization_id,
        role: user.role,
        permissions: user.permissions || [],
      };
    } catch (error) {
      this.logger.error(`JWT validation error: ${error.message}`);
      throw new UnauthorizedException('Invalid token');
    }
  }

  async validateSupabaseJWT(token: string): Promise<UserContext> {
    try {
      // Verify token with Supabase
      const supabase = this.databaseService.getClient();
      const { data: { user }, error } = await supabase.auth.getUser(token);

      if (error || !user) {
        throw new UnauthorizedException('Invalid Supabase token');
      }

      // Get user profile from our database
      const userProfile = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('user_profiles')
          .select(`
            id,
            email,
            full_name,
            role,
            permissions,
            organization_id,
            organizations!inner(id, name, tier)
          `)
          .eq('id', user.id)
          .single();
      });

      if (!userProfile) {
        throw new UnauthorizedException('User profile not found');
      }

      return {
        id: userProfile.id,
        email: userProfile.email,
        organizationId: userProfile.organization_id,
        role: userProfile.role,
        permissions: userProfile.permissions || [],
      };
    } catch (error) {
      this.logger.error(`Supabase JWT validation error: ${error.message}`);
      throw new UnauthorizedException('Invalid authentication token');
    }
  }

  async validateApiKey(apiKey: string): Promise<UserContext> {
    try {
      // Hash the API key for lookup (in production, use proper hashing)
      const keyHash = Buffer.from(apiKey).toString('base64');

      const apiKeyRecord = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('api_keys')
          .select(`
            id,
            organization_id,
            user_id,
            permissions,
            is_active,
            expires_at,
            user_profiles(id, email, role),
            organizations(id, name, tier)
          `)
          .eq('key_hash', keyHash)
          .eq('is_active', true)
          .single();
      });

      if (!apiKeyRecord) {
        throw new UnauthorizedException('Invalid API key');
      }

      // Check if key is expired
      if (apiKeyRecord.expires_at && new Date(apiKeyRecord.expires_at) < new Date()) {
        throw new UnauthorizedException('API key expired');
      }

      // Update last used timestamp
      await this.databaseService.executeQuery(async (client) => {
        return client
          .from('api_keys')
          .update({ last_used_at: new Date().toISOString() })
          .eq('id', apiKeyRecord.id);
      });

      return {
        id: apiKeyRecord.user_profiles[0].id,
        email: apiKeyRecord.user_profiles[0].email,
        organizationId: apiKeyRecord.organization_id,
        role: apiKeyRecord.user_profiles[0].role,
        permissions: apiKeyRecord.permissions || [],
      };
    } catch (error) {
      this.logger.error(`API key validation error: ${error.message}`);
      throw new UnauthorizedException('Invalid API key');
    }
  }

  generateJWT(user: UserContext): string {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      organizationId: user.organizationId,
      role: user.role,
    };

    return this.jwtService.sign(payload);
  }

  async generateApiKey(userId: string, organizationId: string, name: string): Promise<string> {
    // Generate a secure API key
    const apiKey = `iv_${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('hex')}`;
    const keyHash = Buffer.from(apiKey).toString('base64');
    const keyPrefix = apiKey.substring(0, 8);

    await this.databaseService.executeQuery(async (client) => {
      return client
        .from('api_keys')
        .insert({
          user_id: userId,
          organization_id: organizationId,
          name,
          key_hash: keyHash,
          key_prefix: keyPrefix,
          permissions: ['scan:upload', 'scan:read'],
          expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year
        });
    });

    return apiKey;
  }
}