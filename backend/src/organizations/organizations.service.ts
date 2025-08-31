import { Injectable, Logger, NotFoundException, ConflictException, ForbiddenException } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { UserContext } from '../auth/auth.service';
import {
  CreateOrganizationDto,
  UpdateOrganizationDto,
  OrganizationResponseDto,
  InviteUserDto,
  UserProfileResponseDto,
} from './dto/organization.dto';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class OrganizationsService {
  private readonly logger = new Logger(OrganizationsService.name);

  constructor(private databaseService: DatabaseService) {}

  async createOrganization(createDto: CreateOrganizationDto, user: UserContext): Promise<OrganizationResponseDto> {
    try {
      // Check if slug is already taken
      const existingOrg = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('organizations')
          .select('id')
          .eq('slug', createDto.slug)
          .single();
      });

      if (existingOrg) {
        throw new ConflictException('Organization slug already exists');
      }

      const orgId = uuidv4();
      const now = new Date().toISOString();

      const organization = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('organizations')
          .insert({
            id: orgId,
            name: createDto.name,
            slug: createDto.slug,
            tier: createDto.tier,
            settings: createDto.settings || {},
            subscription_data: createDto.subscriptionData || {},
            created_at: now,
            updated_at: now,
          })
          .select()
          .single();
      });

      // Update user's organization association
      await this.databaseService.executeQuery(async (client) => {
        return client
          .from('user_profiles')
          .update({
            organization_id: orgId,
            role: 'admin', // Creator becomes admin
            updated_at: now,
          })
          .eq('id', user.id);
      });

      this.logger.log(`Created organization ${orgId} for user ${user.id}`);

      return this.mapToOrganizationResponse(organization);
    } catch (error) {
      this.logger.error(`Error creating organization: ${error.message}`, error);
      throw error;
    }
  }

  async getOrganization(user: UserContext): Promise<OrganizationResponseDto> {
    try {
      const organization = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('organizations')
          .select('*')
          .eq('id', user.organizationId)
          .single();
      });

      if (!organization) {
        throw new NotFoundException('Organization not found');
      }

      // Get organization statistics
      const stats = await this.getOrganizationStats(user.organizationId);

      const response = this.mapToOrganizationResponse(organization);
      response.stats = stats;

      return response;
    } catch (error) {
      this.logger.error(`Error fetching organization: ${error.message}`, error);
      throw error;
    }
  }

  async updateOrganization(
    updateDto: UpdateOrganizationDto,
    user: UserContext,
  ): Promise<OrganizationResponseDto> {
    try {
      // Check if user has admin role
      if (user.role !== 'admin') {
        throw new ForbiddenException('Only organization admins can update organization settings');
      }

      const updatedOrg = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('organizations')
          .update({
            ...updateDto,
            updated_at: new Date().toISOString(),
          })
          .eq('id', user.organizationId)
          .select()
          .single();
      });

      if (!updatedOrg) {
        throw new NotFoundException('Organization not found');
      }

      this.logger.log(`Updated organization ${user.organizationId} by user ${user.id}`);

      return this.mapToOrganizationResponse(updatedOrg);
    } catch (error) {
      this.logger.error(`Error updating organization: ${error.message}`, error);
      throw error;
    }
  }

  async getOrganizationUsers(user: UserContext): Promise<UserProfileResponseDto[]> {
    try {
      const usersResult = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('user_profiles')
          .select('*')
          .eq('organization_id', user.organizationId)
          .order('created_at', { ascending: true });
      });

      const users = usersResult || [];
      return users.map(this.mapToUserProfileResponse);
    } catch (error) {
      this.logger.error(`Error fetching organization users: ${error.message}`, error);
      throw error;
    }
  }

  async inviteUser(inviteDto: InviteUserDto, user: UserContext): Promise<{ success: boolean; message: string }> {
    try {
      // Check if user has admin role
      if (user.role !== 'admin') {
        throw new ForbiddenException('Only organization admins can invite users');
      }

      // Check if user is already in the organization
      const existingUser = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('user_profiles')
          .select('id')
          .eq('email', inviteDto.email)
          .eq('organization_id', user.organizationId)
          .single();
      });

      if (existingUser) {
        throw new ConflictException('User is already a member of this organization');
      }

      // In a real implementation, you would:
      // 1. Create an invitation record
      // 2. Send an email invitation
      // 3. Handle the invitation acceptance flow

      // For now, we'll just log the invitation
      this.logger.log(`Invitation sent to ${inviteDto.email} for organization ${user.organizationId}`);

      return {
        success: true,
        message: `Invitation sent to ${inviteDto.email}`,
      };
    } catch (error) {
      this.logger.error(`Error inviting user: ${error.message}`, error);
      throw error;
    }
  }

  private async getOrganizationStats(organizationId: string): Promise<any> {
    try {
      // Get scan statistics
      const scanStats = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('scans')
          .select('id, completed_at')
          .eq('organization_id', organizationId)
          .eq('status', 'completed');
      });

      // Get findings count
      const findingsStats = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('findings')
          .select('id')
          .eq('organization_id', organizationId);
      });

      // Get users count
      const usersStats = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('user_profiles')
          .select('id')
          .eq('organization_id', organizationId);
      });

      const lastScanDate = (scanStats && scanStats.length > 0)
        ? scanStats
            .map(s => new Date(s.completed_at))
            .sort((a, b) => b.getTime() - a.getTime())[0]
            .toISOString()
        : undefined;

      return {
        totalScans: scanStats?.length || 0,
        totalFindings: (findingsStats || []).length,
        totalUsers: (usersStats || []).length,
        lastScanDate,
      };
    } catch (error) {
      this.logger.warn(`Error fetching organization stats: ${error.message}`);
      return {
        totalScans: 0,
        totalFindings: 0,
        totalUsers: 0,
      };
    }
  }

  private mapToOrganizationResponse(org: any): OrganizationResponseDto {
    return {
      id: org.id,
      name: org.name,
      slug: org.slug,
      tier: org.tier,
      settings: org.settings || {},
      subscriptionData: org.subscription_data || {},
      createdAt: org.created_at,
      updatedAt: org.updated_at,
    };
  }

  private mapToUserProfileResponse(user: any): UserProfileResponseDto {
    return {
      id: user.id,
      email: user.email,
      fullName: user.full_name,
      role: user.role,
      permissions: user.permissions || [],
      lastLogin: user.last_login,
      preferences: user.preferences || {},
      createdAt: user.created_at,
    };
  }
}