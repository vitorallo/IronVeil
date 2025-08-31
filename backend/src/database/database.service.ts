import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient, SupabaseClient } from '@supabase/supabase-js';

@Injectable()
export class DatabaseService implements OnModuleInit {
  private supabase: SupabaseClient;
  private readonly logger = new Logger(DatabaseService.name);

  constructor(private configService: ConfigService) {}

  async onModuleInit() {
    try {
      const supabaseUrl = this.configService.get<string>('SUPABASE_URL');
      const supabaseServiceKey = this.configService.get<string>('SUPABASE_SERVICE_ROLE_KEY');

      if (!supabaseUrl || !supabaseServiceKey) {
        throw new Error('Supabase URL and Service Role Key must be provided');
      }

      this.supabase = createClient(supabaseUrl, supabaseServiceKey, {
        auth: {
          autoRefreshToken: false,
          persistSession: false,
        },
      });

      // Test connection
      const { data, error } = await this.supabase
        .from('organizations')
        .select('count', { count: 'exact', head: true });

      if (error) {
        throw error;
      }

      this.logger.log(`✅ Connected to Supabase successfully`);
    } catch (error) {
      this.logger.error(`❌ Failed to connect to Supabase: ${error.message}`);
      throw error;
    }
  }

  getClient(): SupabaseClient {
    if (!this.supabase) {
      throw new Error('Supabase client not initialized');
    }
    return this.supabase;
  }

  async executeQuery<T>(
    query: (client: SupabaseClient) => Promise<{ data: T; error: any }>,
  ): Promise<T> {
    try {
      const { data, error } = await query(this.supabase);
      
      if (error) {
        this.logger.error(`Database query error: ${error.message}`, error);
        throw new Error(`Database error: ${error.message}`);
      }

      return data;
    } catch (error) {
      this.logger.error(`Database service error: ${error.message}`, error);
      throw error;
    }
  }

  async executeRPC<T>(
    functionName: string,
    params: Record<string, any> = {},
  ): Promise<T> {
    try {
      const { data, error } = await this.supabase.rpc(functionName, params);
      
      if (error) {
        this.logger.error(`RPC function error: ${error.message}`, error);
        throw new Error(`Database function error: ${error.message}`);
      }

      return data;
    } catch (error) {
      this.logger.error(`Database RPC error: ${error.message}`, error);
      throw error;
    }
  }
}