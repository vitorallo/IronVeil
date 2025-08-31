import {
  Controller,
  Get,
  Post,
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
import { ScansService } from './scans.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { CreateScanDto, ScanResponseDto, ScanListQueryDto } from './dto/scan.dto';
import { PaginatedResponseDto, BaseResponseDto } from '../common/dto/base.dto';

@ApiTags('scans')
@Controller('scans')
@UseGuards(ThrottlerGuard)
export class ScansController {
  private readonly logger = new Logger(ScansController.name);

  constructor(private scansService: ScansService) {}

  @Post('upload')
  @UseGuards(ApiKeyGuard) // Desktop scanner uses API key authentication
  @ApiOperation({
    summary: 'Upload scan results from desktop application',
    description: 'Accepts JSON scan data from the IronVeil desktop scanner and processes it for storage and analysis.',
  })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'Scan uploaded and processed successfully',
    type: ScanResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid scan data format',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or missing API key',
  })
  async uploadScan(
    @Body() createScanDto: CreateScanDto,
    @Request() req: any,
  ): Promise<ScanResponseDto> {
    this.logger.log(`Received scan upload request from user ${req.user.id}`);
    return this.scansService.uploadScan(createScanDto, req.user);
  }

  @Get()
  @UseGuards(JwtAuthGuard) // Frontend uses JWT authentication
  @ApiBearerAuth('JWT')
  @ApiOperation({
    summary: 'List organization scans',
    description: 'Retrieve paginated list of scans for the authenticated user\'s organization with optional filtering.',
  })
  @ApiQuery({ name: 'page', required: false, type: Number, description: 'Page number (default: 1)' })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Items per page (default: 10)' })
  @ApiQuery({ name: 'scanType', required: false, enum: ['ad_only', 'entra_only', 'hybrid', 'custom'] })
  @ApiQuery({ name: 'status', required: false, enum: ['pending', 'processing', 'completed', 'failed', 'cancelled'] })
  @ApiQuery({ name: 'startDate', required: false, type: String, description: 'Filter from date (ISO 8601)' })
  @ApiQuery({ name: 'endDate', required: false, type: String, description: 'Filter to date (ISO 8601)' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'List of scans retrieved successfully',
    type: PaginatedResponseDto<ScanResponseDto>,
  })
  async getScans(
    @Query() query: ScanListQueryDto,
    @Request() req: any,
  ): Promise<PaginatedResponseDto<ScanResponseDto>> {
    return this.scansService.getScans(query, req.user);
  }

  @Get(':id')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT')
  @ApiOperation({
    summary: 'Get scan details',
    description: 'Retrieve detailed information about a specific scan.',
  })
  @ApiParam({ name: 'id', description: 'Scan UUID' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Scan details retrieved successfully',
    type: ScanResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Scan not found',
  })
  async getScan(
    @Param('id') scanId: string,
    @Request() req: any,
  ): Promise<ScanResponseDto> {
    return this.scansService.getScan(scanId, req.user);
  }

  @Get(':id/results')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT')
  @ApiOperation({
    summary: 'Get detailed scan results',
    description: 'Retrieve complete scan results including all findings and raw data.',
  })
  @ApiParam({ name: 'id', description: 'Scan UUID' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Detailed scan results retrieved successfully',
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Scan not found',
  })
  async getScanResults(
    @Param('id') scanId: string,
    @Request() req: any,
  ): Promise<any> {
    return this.scansService.getScanResults(scanId, req.user);
  }

  @Get(':id/status')
  @UseGuards(ApiKeyGuard) // Allow desktop scanner to check status
  @ApiOperation({
    summary: 'Get scan processing status',
    description: 'Check the current processing status of an uploaded scan.',
  })
  @ApiParam({ name: 'id', description: 'Scan UUID' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Scan status retrieved successfully',
  })
  async getScanStatus(
    @Param('id') scanId: string,
    @Request() req: any,
  ): Promise<{ status: string; message?: string }> {
    const scan = await this.scansService.getScan(scanId, req.user);
    return {
      status: scan.status,
      message: this.getStatusMessage(scan.status),
    };
  }

  private getStatusMessage(status: string): string {
    const messages = {
      pending: 'Scan is queued for processing',
      processing: 'Scan is currently being processed',
      completed: 'Scan processing completed successfully',
      failed: 'Scan processing failed',
      cancelled: 'Scan processing was cancelled',
    };
    return messages[status] || 'Unknown status';
  }
}