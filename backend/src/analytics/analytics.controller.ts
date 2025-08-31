import {
  Controller,
  Get,
  Query,
  UseGuards,
  Request,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiQuery,
} from '@nestjs/swagger';
import { ThrottlerGuard } from '@nestjs/throttler';
import { AnalyticsService } from './analytics.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { DashboardSummaryDto, SecurityTrendsDto, ComplianceScoreDto } from './dto/analytics.dto';

@ApiTags('analytics')
@Controller('analytics')
@UseGuards(ThrottlerGuard, JwtAuthGuard)
@ApiBearerAuth('JWT')
export class AnalyticsController {
  constructor(private analyticsService: AnalyticsService) {}

  @Get('dashboard')
  @ApiOperation({
    summary: 'Get dashboard summary',
    description: 'Retrieve key metrics and statistics for the organization dashboard.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Dashboard summary retrieved successfully',
    type: DashboardSummaryDto,
  })
  async getDashboardSummary(@Request() req: any): Promise<DashboardSummaryDto> {
    return this.analyticsService.getDashboardSummary(req.user);
  }

  @Get('trends')
  @ApiOperation({
    summary: 'Get security trends',
    description: 'Retrieve security metrics and trends over time for analytics charts.',
  })
  @ApiQuery({ name: 'days', required: false, type: Number, description: 'Number of days to analyze (default: 30)' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Security trends retrieved successfully',
    type: SecurityTrendsDto,
  })
  async getSecurityTrends(
    @Query('days') days: number = 30,
    @Request() req: any,
  ): Promise<SecurityTrendsDto> {
    return this.analyticsService.getSecurityTrends(req.user, days);
  }

  @Get('compliance')
  @ApiOperation({
    summary: 'Get compliance scores',
    description: 'Retrieve compliance scores and gaps analysis for various security frameworks.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Compliance scores retrieved successfully',
    type: ComplianceScoreDto,
  })
  async getComplianceScore(@Request() req: any): Promise<ComplianceScoreDto> {
    return this.analyticsService.getComplianceScore(req.user);
  }
}