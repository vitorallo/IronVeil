import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsEnum, IsObject, IsOptional, IsEmail, IsUUID } from 'class-validator';

export enum OrganizationTier {
  COMMUNITY = 'community',
  ENTERPRISE = 'enterprise',
  EASM = 'easm',
}

export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
  VIEWER = 'viewer',
  API_ONLY = 'api_only',
}

export class CreateOrganizationDto {
  @ApiProperty({ description: 'Organization name' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ description: 'URL-friendly organization identifier' })
  @IsString()
  @IsNotEmpty()
  slug: string;

  @ApiProperty({ description: 'Subscription tier', enum: OrganizationTier, default: OrganizationTier.COMMUNITY })
  @IsEnum(OrganizationTier)
  tier: OrganizationTier = OrganizationTier.COMMUNITY;

  @ApiProperty({ description: 'Organization settings', required: false })
  @IsOptional()
  @IsObject()
  settings?: Record<string, any>;

  @ApiProperty({ description: 'Subscription data', required: false })
  @IsOptional()
  @IsObject()
  subscriptionData?: Record<string, any>;
}

export class UpdateOrganizationDto {
  @ApiProperty({ description: 'Organization name', required: false })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  name?: string;

  @ApiProperty({ description: 'Subscription tier', enum: OrganizationTier, required: false })
  @IsOptional()
  @IsEnum(OrganizationTier)
  tier?: OrganizationTier;

  @ApiProperty({ description: 'Organization settings', required: false })
  @IsOptional()
  @IsObject()
  settings?: Record<string, any>;

  @ApiProperty({ description: 'Subscription data', required: false })
  @IsOptional()
  @IsObject()
  subscriptionData?: Record<string, any>;
}

export class OrganizationResponseDto {
  @ApiProperty({ description: 'Organization UUID' })
  id: string;

  @ApiProperty({ description: 'Organization name' })
  name: string;

  @ApiProperty({ description: 'URL-friendly identifier' })
  slug: string;

  @ApiProperty({ description: 'Subscription tier', enum: OrganizationTier })
  tier: OrganizationTier;

  @ApiProperty({ description: 'Organization settings' })
  settings: Record<string, any>;

  @ApiProperty({ description: 'Subscription information' })
  subscriptionData: Record<string, any>;

  @ApiProperty({ description: 'Creation timestamp' })
  createdAt: string;

  @ApiProperty({ description: 'Last update timestamp' })
  updatedAt: string;

  @ApiProperty({ description: 'Organization statistics', required: false })
  stats?: {
    totalScans: number;
    totalFindings: number;
    totalUsers: number;
    lastScanDate?: string;
  };
}

export class InviteUserDto {
  @ApiProperty({ description: 'Email address of user to invite' })
  @IsEmail()
  email: string;

  @ApiProperty({ description: 'Role to assign to user', enum: UserRole, default: UserRole.USER })
  @IsEnum(UserRole)
  role: UserRole = UserRole.USER;

  @ApiProperty({ description: 'Custom permissions', required: false })
  @IsOptional()
  @IsString({ each: true })
  permissions?: string[];

  @ApiProperty({ description: 'Invitation message', required: false })
  @IsOptional()
  @IsString()
  message?: string;
}

export class UserProfileResponseDto {
  @ApiProperty({ description: 'User UUID' })
  id: string;

  @ApiProperty({ description: 'Email address' })
  email: string;

  @ApiProperty({ description: 'Full name' })
  fullName?: string;

  @ApiProperty({ description: 'User role', enum: UserRole })
  role: UserRole;

  @ApiProperty({ description: 'User permissions' })
  permissions: string[];

  @ApiProperty({ description: 'Last login timestamp' })
  lastLogin?: string;

  @ApiProperty({ description: 'User preferences' })
  preferences: Record<string, any>;

  @ApiProperty({ description: 'Account creation timestamp' })
  createdAt: string;
}