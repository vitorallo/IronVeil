import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { UserContext } from '../auth/auth.service';
import { CreateScanDto, ScanResponseDto, ScanListQueryDto, ScanStatus } from './dto/scan.dto';
import { PaginatedResponseDto } from '../common/dto/base.dto';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class ScansService {
  private readonly logger = new Logger(ScansService.name);

  constructor(private databaseService: DatabaseService) {}

  async uploadScan(createScanDto: CreateScanDto, user: UserContext): Promise<ScanResponseDto> {
    try {
      this.logger.log(`Processing scan upload for user ${user.id} in organization ${user.organizationId}`);

      // Create the scan record
      const scanId = uuidv4();
      const now = new Date().toISOString();

      // Calculate findings summary
      const findingsSummary = this.calculateFindingsSummary(createScanDto.findings);

      // Prepare raw scan data
      const rawData = {
        findings: createScanDto.findings,
        execution: createScanDto.execution,
        metadata: createScanDto.metadata || {},
      };

      // Process scan results (normalize findings)
      const processedResults = {
        findingsCount: createScanDto.findings.length,
        findingsSummary,
        averageRiskScore: this.calculateAverageRiskScore(createScanDto.findings),
        categorySummary: this.calculateCategorySummary(createScanDto.findings),
      };

      const scan = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('scans')
          .insert({
            id: scanId,
            organization_id: user.organizationId,
            user_id: user.id,
            name: createScanDto.name,
            description: createScanDto.description,
            scan_type: createScanDto.scanType,
            status: ScanStatus.PROCESSING,
            raw_data: rawData,
            processed_results: processedResults,
            metadata: createScanDto.metadata || {},
            overall_score: createScanDto.overallScore,
            risk_level: createScanDto.riskLevel,
            findings_summary: findingsSummary,
            started_at: createScanDto.execution.startTime,
            completed_at: createScanDto.execution.endTime,
            processing_duration: this.calculateProcessingDuration(
              createScanDto.execution.startTime,
              createScanDto.execution.endTime
            ),
            created_at: now,
            updated_at: now,
          })
          .select()
          .single();
      });

      // Process individual findings
      await this.processFindings(scanId, createScanDto.findings, user.organizationId);

      // Update scan status to completed
      const completedScan = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('scans')
          .update({
            status: ScanStatus.COMPLETED,
            updated_at: new Date().toISOString(),
          })
          .eq('id', scanId)
          .select()
          .single();
      });

      this.logger.log(`Successfully processed scan upload ${scanId}`);

      return this.mapToScanResponse(completedScan);
    } catch (error) {
      this.logger.error(`Error uploading scan: ${error.message}`, error);
      throw new BadRequestException(`Failed to process scan upload: ${error.message}`);
    }
  }

  async getScans(query: ScanListQueryDto, user: UserContext): Promise<PaginatedResponseDto<ScanResponseDto>> {
    try {
      const { page = 1, limit = 10, scanType, status, startDate, endDate } = query;
      const offset = (page - 1) * limit;

      // Build query with filters
      let baseQuery = this.databaseService.getClient()
        .from('scans')
        .select('*', { count: 'exact' })
        .eq('organization_id', user.organizationId)
        .order('created_at', { ascending: false })
        .range(offset, offset + limit - 1);

      if (scanType) {
        baseQuery = baseQuery.eq('scan_type', scanType);
      }

      if (status) {
        baseQuery = baseQuery.eq('status', status);
      }

      if (startDate) {
        baseQuery = baseQuery.gte('created_at', startDate);
      }

      if (endDate) {
        baseQuery = baseQuery.lte('created_at', endDate);
      }

      const result = await this.databaseService.executeQuery(async () => baseQuery);

      const scans = (result || []).map(scan => this.mapToScanResponse(scan));
      const total = scans.length;

      return new PaginatedResponseDto(scans, page, limit, total);
    } catch (error) {
      this.logger.error(`Error fetching scans: ${error.message}`, error);
      throw error;
    }
  }

  async getScan(scanId: string, user: UserContext): Promise<ScanResponseDto> {
    try {
      const scan = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('scans')
          .select('*')
          .eq('id', scanId)
          .eq('organization_id', user.organizationId)
          .single();
      });

      if (!scan) {
        throw new NotFoundException('Scan not found');
      }

      return this.mapToScanResponse(scan);
    } catch (error) {
      this.logger.error(`Error fetching scan ${scanId}: ${error.message}`, error);
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new BadRequestException(`Failed to fetch scan: ${error.message}`);
    }
  }

  async getScanResults(scanId: string, user: UserContext): Promise<any> {
    try {
      // Get scan with findings
      const result = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('scans')
          .select(`
            *,
            findings (*)
          `)
          .eq('id', scanId)
          .eq('organization_id', user.organizationId)
          .single();
      });

      if (!result) {
        throw new NotFoundException('Scan not found');
      }

      return {
        scan: this.mapToScanResponse(result),
        findings: result.findings || [],
        rawData: result.raw_data,
        processedResults: result.processed_results,
      };
    } catch (error) {
      this.logger.error(`Error fetching scan results ${scanId}: ${error.message}`, error);
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new BadRequestException(`Failed to fetch scan results: ${error.message}`);
    }
  }

  private async processFindings(scanId: string, findings: any[], organizationId: string): Promise<void> {
    if (!findings?.length) {
      return;
    }

    const findingRecords = findings.map(finding => ({
      id: uuidv4(),
      scan_id: scanId,
      organization_id: organizationId,
      rule_id: finding.ruleId,
      rule_name: finding.ruleName,
      category: finding.category,
      severity: finding.severity,
      title: finding.title,
      description: finding.description,
      affected_objects: finding.affectedObjects || [],
      remediation: finding.remediation,
      risk_score: finding.riskScore,
      impact_score: finding.impactScore,
      likelihood_score: finding.likelihoodScore,
      status: 'open',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    }));

    await this.databaseService.executeQuery(async (client) => {
      return client
        .from('findings')
        .insert(findingRecords);
    });
  }

  private calculateFindingsSummary(findings: any[]): Record<string, number> {
    return findings.reduce((summary, finding) => {
      const severity = finding.severity || 'unknown';
      summary[severity] = (summary[severity] || 0) + 1;
      return summary;
    }, {});
  }

  private calculateAverageRiskScore(findings: any[]): number {
    if (!findings?.length) return 0;
    const totalRisk = findings.reduce((sum, finding) => sum + (finding.riskScore || 0), 0);
    return Math.round(totalRisk / findings.length);
  }

  private calculateCategorySummary(findings: any[]): Record<string, number> {
    return findings.reduce((summary, finding) => {
      const category = finding.category || 'unknown';
      summary[category] = (summary[category] || 0) + 1;
      return summary;
    }, {});
  }

  private calculateProcessingDuration(startTime: string, endTime: string): string {
    const start = new Date(startTime);
    const end = new Date(endTime);
    const duration = end.getTime() - start.getTime();
    return `${Math.round(duration / 1000)} seconds`;
  }

  private mapToScanResponse(scan: any): ScanResponseDto {
    return {
      id: scan.id,
      name: scan.name,
      description: scan.description,
      scanType: scan.scan_type,
      status: scan.status,
      overallScore: scan.overall_score,
      riskLevel: scan.risk_level,
      findingsSummary: scan.findings_summary || {},
      startedAt: scan.started_at,
      completedAt: scan.completed_at,
      processingDuration: scan.processing_duration,
      createdAt: scan.created_at,
      updatedAt: scan.updated_at,
    };
  }
}