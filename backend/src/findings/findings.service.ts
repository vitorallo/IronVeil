import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { UserContext } from '../auth/auth.service';
import {
  FindingResponseDto,
  FindingListQueryDto,
  UpdateFindingDto,
  FindingsSummaryDto,
  FindingSeverity,
  FindingStatus,
} from './dto/finding.dto';
import { PaginatedResponseDto } from '../common/dto/base.dto';

@Injectable()
export class FindingsService {
  private readonly logger = new Logger(FindingsService.name);

  constructor(private databaseService: DatabaseService) {}

  async getFindings(query: FindingListQueryDto, user: UserContext): Promise<PaginatedResponseDto<FindingResponseDto>> {
    try {
      const {
        page = 1,
        limit = 10,
        scanId,
        severity,
        status,
        category,
        ruleId,
        search,
        startDate,
        endDate,
        sortBy = 'createdAt',
        sortOrder = 'desc',
      } = query;

      const offset = (page - 1) * limit;

      // Build the query
      let baseQuery = this.databaseService.getClient()
        .from('findings')
        .select('*', { count: 'exact' })
        .eq('organization_id', user.organizationId);

      // Apply filters
      if (scanId) {
        baseQuery = baseQuery.eq('scan_id', scanId);
      }

      if (severity) {
        baseQuery = baseQuery.eq('severity', severity);
      }

      if (status) {
        baseQuery = baseQuery.eq('status', status);
      }

      if (category) {
        baseQuery = baseQuery.eq('category', category);
      }

      if (ruleId) {
        baseQuery = baseQuery.eq('rule_id', ruleId);
      }

      if (search) {
        baseQuery = baseQuery.or(`title.ilike.%${search}%,description.ilike.%${search}%`);
      }

      if (startDate) {
        baseQuery = baseQuery.gte('created_at', startDate);
      }

      if (endDate) {
        baseQuery = baseQuery.lte('created_at', endDate);
      }

      // Apply sorting and pagination
      const ascending = sortOrder === 'asc';
      baseQuery = baseQuery
        .order(sortBy, { ascending })
        .range(offset, offset + limit - 1);

      const result = await this.databaseService.executeQuery(async () => baseQuery);

      // For now, we'll get count separately since our database service doesn't support count queries properly
      const findings = (result || []).map(finding => this.mapToFindingResponse(finding));
      const total = findings.length;

      return new PaginatedResponseDto(findings, page, limit, total);
    } catch (error) {
      this.logger.error(`Error fetching findings: ${error.message}`, error);
      throw new BadRequestException(`Failed to fetch findings: ${error.message}`);
    }
  }

  async getFinding(findingId: string, user: UserContext): Promise<FindingResponseDto> {
    try {
      const finding = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('findings')
          .select('*')
          .eq('id', findingId)
          .eq('organization_id', user.organizationId)
          .single();
      });

      if (!finding) {
        throw new NotFoundException('Finding not found');
      }

      return this.mapToFindingResponse(finding);
    } catch (error) {
      this.logger.error(`Error fetching finding ${findingId}: ${error.message}`, error);
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new BadRequestException(`Failed to fetch finding: ${error.message}`);
    }
  }

  async updateFinding(
    findingId: string,
    updateDto: UpdateFindingDto,
    user: UserContext,
  ): Promise<FindingResponseDto> {
    try {
      const updateData: any = {
        ...updateDto,
        updated_at: new Date().toISOString(),
      };

      // If status is being changed to resolved, set resolved_at timestamp
      if (updateDto.status === FindingStatus.RESOLVED) {
        updateData.resolved_at = new Date().toISOString();
      }

      const updatedFinding = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('findings')
          .update(updateData)
          .eq('id', findingId)
          .eq('organization_id', user.organizationId)
          .select()
          .single();
      });

      if (!updatedFinding) {
        throw new NotFoundException('Finding not found');
      }

      this.logger.log(`Updated finding ${findingId} by user ${user.id}`);

      return this.mapToFindingResponse(updatedFinding);
    } catch (error) {
      this.logger.error(`Error updating finding ${findingId}: ${error.message}`, error);
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new BadRequestException(`Failed to update finding: ${error.message}`);
    }
  }

  async getFindingsSummary(user: UserContext): Promise<FindingsSummaryDto> {
    try {
      // Get all findings for the organization
      const findingsResult = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('findings')
          .select('severity, status, category, risk_score, created_at, resolved_at')
          .eq('organization_id', user.organizationId);
      });

      const findings = findingsResult || [];
      const now = new Date();
      const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

      // Calculate summary statistics
      const total = findings.length;
      const bySeverity = this.groupBy(findings, 'severity');
      const byStatus = this.groupBy(findings, 'status');
      const byCategory = this.groupBy(findings, 'category');

      const recentCount = findings.filter(f => 
        new Date(f.created_at) > thirtyDaysAgo
      ).length;

      const resolvedCount = findings.filter(f => 
        f.status === FindingStatus.RESOLVED
      ).length;

      const criticalOpen = findings.filter(f => 
        f.severity === FindingSeverity.CRITICAL && f.status === FindingStatus.OPEN
      ).length;

      const averageRiskScore = findings.length > 0
        ? Math.round(findings.reduce((sum, f) => sum + (f.risk_score || 0), 0) / findings.length)
        : 0;

      return {
        total,
        bySeverity: this.fillSeverityGaps(bySeverity),
        byStatus: this.fillStatusGaps(byStatus),
        byCategory,
        recentCount,
        resolvedCount,
        criticalOpen,
        averageRiskScore,
      };
    } catch (error) {
      this.logger.error(`Error generating findings summary: ${error.message}`, error);
      throw new BadRequestException(`Failed to generate findings summary: ${error.message}`);
    }
  }

  async getFindingsByRule(user: UserContext): Promise<Record<string, number>> {
    try {
      const findingsResult = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('findings')
          .select('rule_id, rule_name')
          .eq('organization_id', user.organizationId)
          .eq('status', FindingStatus.OPEN);
      });

      const findings = findingsResult || [];
      return this.groupBy(findings, 'rule_id');
    } catch (error) {
      this.logger.error(`Error fetching findings by rule: ${error.message}`, error);
      throw new BadRequestException(`Failed to fetch findings by rule: ${error.message}`);
    }
  }

  private groupBy(array: any[], key: string): Record<string, number> {
    return array.reduce((groups, item) => {
      const value = item[key] || 'unknown';
      groups[value] = (groups[value] || 0) + 1;
      return groups;
    }, {});
  }

  private fillSeverityGaps(bySeverity: Record<string, number>): Record<FindingSeverity, number> {
    return {
      [FindingSeverity.CRITICAL]: bySeverity[FindingSeverity.CRITICAL] || 0,
      [FindingSeverity.HIGH]: bySeverity[FindingSeverity.HIGH] || 0,
      [FindingSeverity.MEDIUM]: bySeverity[FindingSeverity.MEDIUM] || 0,
      [FindingSeverity.LOW]: bySeverity[FindingSeverity.LOW] || 0,
    };
  }

  private fillStatusGaps(byStatus: Record<string, number>): Record<FindingStatus, number> {
    return {
      [FindingStatus.OPEN]: byStatus[FindingStatus.OPEN] || 0,
      [FindingStatus.IN_PROGRESS]: byStatus[FindingStatus.IN_PROGRESS] || 0,
      [FindingStatus.RESOLVED]: byStatus[FindingStatus.RESOLVED] || 0,
      [FindingStatus.FALSE_POSITIVE]: byStatus[FindingStatus.FALSE_POSITIVE] || 0,
      [FindingStatus.ACCEPTED_RISK]: byStatus[FindingStatus.ACCEPTED_RISK] || 0,
    };
  }

  private mapToFindingResponse(finding: any): FindingResponseDto {
    return {
      id: finding.id,
      scanId: finding.scan_id,
      ruleId: finding.rule_id,
      ruleName: finding.rule_name,
      category: finding.category,
      severity: finding.severity,
      title: finding.title,
      description: finding.description,
      affectedObjects: finding.affected_objects || [],
      remediation: finding.remediation,
      externalReferences: finding.external_references || [],
      riskScore: finding.risk_score,
      impactScore: finding.impact_score,
      likelihoodScore: finding.likelihood_score,
      status: finding.status,
      assigneeId: finding.assignee_id,
      resolvedAt: finding.resolved_at,
      resolutionNotes: finding.resolution_notes,
      createdAt: finding.created_at,
      updatedAt: finding.updated_at,
    };
  }
}