import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsEnum, IsObject, IsOptional, IsArray, ValidateNested, IsInt, Min, Max, IsUUID, IsISO8601 } from 'class-validator';
import { Type } from 'class-transformer';

export enum ScanType {
  AD_ONLY = 'ad_only',
  ENTRA_ONLY = 'entra_only',
  HYBRID = 'hybrid',
  CUSTOM = 'custom',
}

export enum ScanStatus {
  PENDING = 'pending',
  PROCESSING = 'processing',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled',
}

export enum RiskLevel {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info',
}

export class FindingDto {
  @ApiProperty({ description: 'Unique identifier for the finding' })
  @IsString()
  @IsNotEmpty()
  id: string;

  @ApiProperty({ description: 'Rule that generated this finding' })
  @IsString()
  @IsNotEmpty()
  ruleId: string;

  @ApiProperty({ description: 'Human-readable rule name' })
  @IsString()
  @IsNotEmpty()
  ruleName: string;

  @ApiProperty({ description: 'Finding category' })
  @IsString()
  @IsNotEmpty()
  category: string;

  @ApiProperty({ description: 'Severity level', enum: RiskLevel })
  @IsEnum(RiskLevel)
  severity: RiskLevel;

  @ApiProperty({ description: 'Finding title/summary' })
  @IsString()
  @IsNotEmpty()
  title: string;

  @ApiProperty({ description: 'Detailed description of the finding' })
  @IsString()
  @IsNotEmpty()
  description: string;

  @ApiProperty({ description: 'Objects affected by this finding' })
  @IsArray()
  affectedObjects: any[];

  @ApiProperty({ description: 'Remediation guidance', required: false })
  @IsOptional()
  @IsString()
  remediation?: string;

  @ApiProperty({ description: 'Risk score (0-100)' })
  @IsInt()
  @Min(0)
  @Max(100)
  riskScore: number;

  @ApiProperty({ description: 'Impact score (0-10)' })
  @IsInt()
  @Min(0)
  @Max(10)
  impactScore: number;

  @ApiProperty({ description: 'Likelihood score (0-10)' })
  @IsInt()
  @Min(0)
  @Max(10)
  likelihoodScore: number;
}

export class ScanExecutionMetadataDto {
  @ApiProperty({ description: 'Scan start time (ISO 8601)' })
  @IsISO8601()
  startTime: string;

  @ApiProperty({ description: 'Scan end time (ISO 8601)' })
  @IsISO8601()
  endTime: string;

  @ApiProperty({ description: 'List of rules executed' })
  @IsArray()
  @IsString({ each: true })
  rulesExecuted: string[];

  @ApiProperty({ description: 'Environment information' })
  @IsObject()
  environment: {
    adDomains?: string[];
    entraIdTenant?: string;
    computerName?: string;
    domain?: string;
    username?: string;
  };

  @ApiProperty({ description: 'Duration in seconds' })
  @IsInt()
  @Min(0)
  durationSeconds: number;

  @ApiProperty({ description: 'Number of objects scanned' })
  @IsInt()
  @Min(0)
  objectsScanned: number;

  @ApiProperty({ description: 'Number of rules with errors' })
  @IsInt()
  @Min(0)
  rulesWithErrors: number;
}

export class CreateScanDto {
  @ApiProperty({ description: 'Human-readable scan name' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ description: 'Optional scan description' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiProperty({ description: 'Type of scan performed', enum: ScanType })
  @IsEnum(ScanType)
  scanType: ScanType;

  @ApiProperty({ description: 'Array of security findings', type: [FindingDto] })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => FindingDto)
  findings: FindingDto[];

  @ApiProperty({ description: 'Overall security score (0-100)' })
  @IsInt()
  @Min(0)
  @Max(100)
  overallScore: number;

  @ApiProperty({ description: 'Risk level assessment', enum: RiskLevel })
  @IsEnum(RiskLevel)
  riskLevel: RiskLevel;

  @ApiProperty({ description: 'Scan execution metadata' })
  @IsObject()
  @ValidateNested()
  @Type(() => ScanExecutionMetadataDto)
  execution: ScanExecutionMetadataDto;

  @ApiProperty({ description: 'Additional metadata', required: false })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, any>;
}

export class ScanResponseDto {
  @ApiProperty({ description: 'Unique scan identifier' })
  @IsUUID()
  id: string;

  @ApiProperty({ description: 'Scan name' })
  name: string;

  @ApiProperty({ description: 'Scan description' })
  description?: string;

  @ApiProperty({ description: 'Scan type', enum: ScanType })
  scanType: ScanType;

  @ApiProperty({ description: 'Current scan status', enum: ScanStatus })
  status: ScanStatus;

  @ApiProperty({ description: 'Overall security score' })
  overallScore?: number;

  @ApiProperty({ description: 'Risk level', enum: RiskLevel })
  riskLevel?: RiskLevel;

  @ApiProperty({ description: 'Number of findings by severity' })
  findingsSummary: Record<string, number>;

  @ApiProperty({ description: 'Scan start time' })
  startedAt?: string;

  @ApiProperty({ description: 'Scan completion time' })
  completedAt?: string;

  @ApiProperty({ description: 'Processing duration' })
  processingDuration?: string;

  @ApiProperty({ description: 'Creation timestamp' })
  createdAt: string;

  @ApiProperty({ description: 'Last update timestamp' })
  updatedAt: string;
}

export class ScanListQueryDto {
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

  @ApiProperty({ description: 'Filter by scan type', enum: ScanType, required: false })
  @IsOptional()
  @IsEnum(ScanType)
  scanType?: ScanType;

  @ApiProperty({ description: 'Filter by scan status', enum: ScanStatus, required: false })
  @IsOptional()
  @IsEnum(ScanStatus)
  status?: ScanStatus;

  @ApiProperty({ description: 'Filter scans after this date (ISO 8601)', required: false })
  @IsOptional()
  @IsISO8601()
  startDate?: string;

  @ApiProperty({ description: 'Filter scans before this date (ISO 8601)', required: false })
  @IsOptional()
  @IsISO8601()
  endDate?: string;
}