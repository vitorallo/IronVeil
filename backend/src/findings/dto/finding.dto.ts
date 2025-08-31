import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsEnum, IsOptional, IsArray, IsInt, Min, Max, IsUUID, IsISO8601 } from 'class-validator';

export enum FindingSeverity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
}

export enum FindingStatus {
  OPEN = 'open',
  IN_PROGRESS = 'in_progress',
  RESOLVED = 'resolved',
  FALSE_POSITIVE = 'false_positive',
  ACCEPTED_RISK = 'accepted_risk',
}

export class FindingResponseDto {
  @ApiProperty({ description: 'Finding UUID' })
  id: string;

  @ApiProperty({ description: 'Associated scan UUID' })
  scanId: string;

  @ApiProperty({ description: 'Rule identifier' })
  ruleId: string;

  @ApiProperty({ description: 'Human-readable rule name' })
  ruleName: string;

  @ApiProperty({ description: 'Finding category' })
  category: string;

  @ApiProperty({ description: 'Severity level', enum: FindingSeverity })
  severity: FindingSeverity;

  @ApiProperty({ description: 'Finding title' })
  title: string;

  @ApiProperty({ description: 'Detailed description' })
  description: string;

  @ApiProperty({ description: 'Affected objects' })
  affectedObjects: any[];

  @ApiProperty({ description: 'Remediation guidance' })
  remediation?: string;

  @ApiProperty({ description: 'External references' })
  externalReferences: any[];

  @ApiProperty({ description: 'Risk score (0-100)' })
  riskScore: number;

  @ApiProperty({ description: 'Impact score (0-10)' })
  impactScore: number;

  @ApiProperty({ description: 'Likelihood score (0-10)' })
  likelihoodScore: number;

  @ApiProperty({ description: 'Current status', enum: FindingStatus })
  status: FindingStatus;

  @ApiProperty({ description: 'Assigned user UUID', nullable: true })
  assigneeId?: string;

  @ApiProperty({ description: 'Resolution timestamp' })
  resolvedAt?: string;

  @ApiProperty({ description: 'Resolution notes' })
  resolutionNotes?: string;

  @ApiProperty({ description: 'Creation timestamp' })
  createdAt: string;

  @ApiProperty({ description: 'Last update timestamp' })
  updatedAt: string;
}

export class FindingListQueryDto {
  @ApiProperty({ description: 'Page number', minimum: 1, default: 1, required: false })
  @IsOptional()
  @IsInt()
  @Min(1)
  page?: number = 1;

  @ApiProperty({ description: 'Items per page', minimum: 1, maximum: 100, default: 10, required: false })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number = 10;

  @ApiProperty({ description: 'Filter by scan UUID', required: false })
  @IsOptional()
  @IsUUID()
  scanId?: string;

  @ApiProperty({ description: 'Filter by severity', enum: FindingSeverity, required: false })
  @IsOptional()
  @IsEnum(FindingSeverity)
  severity?: FindingSeverity;

  @ApiProperty({ description: 'Filter by status', enum: FindingStatus, required: false })
  @IsOptional()
  @IsEnum(FindingStatus)
  status?: FindingStatus;

  @ApiProperty({ description: 'Filter by category', required: false })
  @IsOptional()
  @IsString()
  category?: string;

  @ApiProperty({ description: 'Filter by rule ID', required: false })
  @IsOptional()
  @IsString()
  ruleId?: string;

  @ApiProperty({ description: 'Search in title and description', required: false })
  @IsOptional()
  @IsString()
  search?: string;

  @ApiProperty({ description: 'Filter findings after this date (ISO 8601)', required: false })
  @IsOptional()
  @IsISO8601()
  startDate?: string;

  @ApiProperty({ description: 'Filter findings before this date (ISO 8601)', required: false })
  @IsOptional()
  @IsISO8601()
  endDate?: string;

  @ApiProperty({ description: 'Sort field', required: false })
  @IsOptional()
  @IsEnum(['createdAt', 'riskScore', 'severity', 'title'])
  sortBy?: string = 'createdAt';

  @ApiProperty({ description: 'Sort order', required: false })
  @IsOptional()
  @IsEnum(['asc', 'desc'])
  sortOrder?: string = 'desc';
}

export class UpdateFindingDto {
  @ApiProperty({ description: 'Finding status', enum: FindingStatus, required: false })
  @IsOptional()
  @IsEnum(FindingStatus)
  status?: FindingStatus;

  @ApiProperty({ description: 'Assign to user UUID', required: false })
  @IsOptional()
  @IsUUID()
  assigneeId?: string;

  @ApiProperty({ description: 'Resolution notes', required: false })
  @IsOptional()
  @IsString()
  resolutionNotes?: string;
}

export class FindingsSummaryDto {
  @ApiProperty({ description: 'Total number of findings' })
  total: number;

  @ApiProperty({ description: 'Findings by severity' })
  bySeverity: Record<FindingSeverity, number>;

  @ApiProperty({ description: 'Findings by status' })
  byStatus: Record<FindingStatus, number>;

  @ApiProperty({ description: 'Findings by category' })
  byCategory: Record<string, number>;

  @ApiProperty({ description: 'Recent findings (last 30 days)' })
  recentCount: number;

  @ApiProperty({ description: 'Resolved findings count' })
  resolvedCount: number;

  @ApiProperty({ description: 'Open critical findings' })
  criticalOpen: number;

  @ApiProperty({ description: 'Average risk score' })
  averageRiskScore: number;
}