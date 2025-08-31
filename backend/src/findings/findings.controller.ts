import {
  Controller,
  Get,
  Put,
  Param,
  Body,
  Query,
  UseGuards,
  Request,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiQuery,
  ApiParam,
} from '@nestjs/swagger';
import { ThrottlerGuard } from '@nestjs/throttler';
import { FindingsService } from './findings.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import {
  FindingResponseDto,
  FindingListQueryDto,
  UpdateFindingDto,
  FindingsSummaryDto,
} from './dto/finding.dto';
import { PaginatedResponseDto } from '../common/dto/base.dto';

@ApiTags('findings')
@Controller('findings')
@UseGuards(ThrottlerGuard, JwtAuthGuard)
@ApiBearerAuth('JWT')
export class FindingsController {
  private readonly logger = new Logger(FindingsController.name);

  constructor(private findingsService: FindingsService) {}

  @Get()
  @ApiOperation({
    summary: 'List organization findings',
    description: 'Retrieve paginated list of security findings with filtering and search capabilities.',
  })
  @ApiQuery({ name: 'page', required: false, type: Number, description: 'Page number (default: 1)' })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Items per page (default: 10)' })
  @ApiQuery({ name: 'scanId', required: false, type: String, description: 'Filter by scan UUID' })
  @ApiQuery({ name: 'severity', required: false, enum: ['critical', 'high', 'medium', 'low'] })
  @ApiQuery({ name: 'status', required: false, enum: ['open', 'in_progress', 'resolved', 'false_positive', 'accepted_risk'] })
  @ApiQuery({ name: 'category', required: false, type: String, description: 'Filter by category' })
  @ApiQuery({ name: 'ruleId', required: false, type: String, description: 'Filter by rule ID' })
  @ApiQuery({ name: 'search', required: false, type: String, description: 'Search in title and description' })
  @ApiQuery({ name: 'startDate', required: false, type: String, description: 'Filter from date (ISO 8601)' })
  @ApiQuery({ name: 'endDate', required: false, type: String, description: 'Filter to date (ISO 8601)' })
  @ApiQuery({ name: 'sortBy', required: false, enum: ['createdAt', 'riskScore', 'severity', 'title'] })
  @ApiQuery({ name: 'sortOrder', required: false, enum: ['asc', 'desc'] })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'List of findings retrieved successfully',
    type: PaginatedResponseDto<FindingResponseDto>,
  })
  async getFindings(
    @Query() query: FindingListQueryDto,
    @Request() req: any,
  ): Promise<PaginatedResponseDto<FindingResponseDto>> {
    return this.findingsService.getFindings(query, req.user);
  }

  @Get('summary')
  @ApiOperation({
    summary: 'Get findings summary',
    description: 'Retrieve aggregated statistics and summary of organization findings.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Findings summary retrieved successfully',
    type: FindingsSummaryDto,
  })
  async getFindingsSummary(@Request() req: any): Promise<FindingsSummaryDto> {
    return this.findingsService.getFindingsSummary(req.user);
  }

  @Get('by-rule')
  @ApiOperation({
    summary: 'Get findings grouped by rule',
    description: 'Retrieve count of open findings grouped by rule ID for trend analysis.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Findings by rule retrieved successfully',
  })
  async getFindingsByRule(@Request() req: any): Promise<Record<string, number>> {
    return this.findingsService.getFindingsByRule(req.user);
  }

  @Get(':id')
  @ApiOperation({
    summary: 'Get finding details',
    description: 'Retrieve detailed information about a specific finding.',
  })
  @ApiParam({ name: 'id', description: 'Finding UUID' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Finding details retrieved successfully',
    type: FindingResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Finding not found',
  })
  async getFinding(
    @Param('id') findingId: string,
    @Request() req: any,
  ): Promise<FindingResponseDto> {
    return this.findingsService.getFinding(findingId, req.user);
  }

  @Put(':id')
  @ApiOperation({
    summary: 'Update finding',
    description: 'Update finding status, assignment, or resolution notes.',
  })
  @ApiParam({ name: 'id', description: 'Finding UUID' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Finding updated successfully',
    type: FindingResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Finding not found',
  })
  async updateFinding(
    @Param('id') findingId: string,
    @Body() updateDto: UpdateFindingDto,
    @Request() req: any,
  ): Promise<FindingResponseDto> {
    this.logger.log(`Updating finding ${findingId} by user ${req.user.id}`);
    return this.findingsService.updateFinding(findingId, updateDto, req.user);
  }
}