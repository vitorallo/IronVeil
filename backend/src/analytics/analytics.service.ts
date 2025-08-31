import { Injectable, Logger } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { UserContext } from '../auth/auth.service';
import { DashboardSummaryDto, SecurityTrendsDto, ComplianceScoreDto } from './dto/analytics.dto';

@Injectable()
export class AnalyticsService {
  private readonly logger = new Logger(AnalyticsService.name);

  constructor(private databaseService: DatabaseService) {}

  async getDashboardSummary(user: UserContext): Promise<DashboardSummaryDto> {
    try {
      const [scans, findings, recentActivity] = await Promise.all([
        this.getScansData(user.organizationId),
        this.getFindingsData(user.organizationId),
        this.getRecentActivity(user.organizationId),
      ]);

      const totalScans = scans.length;
      const totalFindings = findings.length;
      const activeFindings = findings.filter(f => f.status === 'open' || f.status === 'in_progress').length;
      const resolvedFindings = findings.filter(f => f.status === 'resolved').length;
      const criticalFindings = findings.filter(f => f.severity === 'critical' && f.status === 'open').length;
      const highSeverityFindings = findings.filter(f => f.severity === 'high' && f.status === 'open').length;

      // Calculate overall security score (weighted average of recent scans)
      const recentScans = scans
        .filter(s => s.overall_score !== null)
        .sort((a, b) => new Date(b.completed_at).getTime() - new Date(a.completed_at).getTime())
        .slice(0, 5);

      const overallSecurityScore = recentScans.length > 0
        ? Math.round(recentScans.reduce((sum, scan) => sum + scan.overall_score, 0) / recentScans.length)
        : 0;

      // Calculate score trend (compare last 2 scans)
      const scoreTrend = recentScans.length >= 2
        ? recentScans[0].overall_score - recentScans[1].overall_score
        : 0;

      // Get last scan date
      const lastScanDate = scans.length > 0
        ? scans.sort((a, b) => new Date(b.completed_at).getTime() - new Date(a.completed_at).getTime())[0].completed_at
        : undefined;

      // Calculate scan frequency (scans per month)
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const recentScansCount = scans.filter(s => new Date(s.completed_at) > thirtyDaysAgo).length;
      const scanFrequency = recentScansCount;

      // Get top risk categories
      const topRiskCategories = this.getTopRiskCategories(findings);

      return {
        totalScans,
        totalFindings,
        activeFindings,
        resolvedFindings,
        overallSecurityScore,
        scoreTrend,
        criticalFindings,
        highSeverityFindings,
        lastScanDate,
        scanFrequency,
        topRiskCategories,
        recentActivity,
      };
    } catch (error) {
      this.logger.error(`Error generating dashboard summary: ${error.message}`, error);
      throw error;
    }
  }

  async getSecurityTrends(user: UserContext, days: number = 30): Promise<SecurityTrendsDto> {
    try {
      const endDate = new Date();
      const startDate = new Date(endDate.getTime() - days * 24 * 60 * 60 * 1000);

      // Get analytics snapshots for the period
      const snapshots = await this.databaseService.executeQuery(async (client) => {
        return client
          .from('analytics_snapshots')
          .select('*')
          .eq('organization_id', user.organizationId)
          .gte('snapshot_date', startDate.toISOString().split('T')[0])
          .lte('snapshot_date', endDate.toISOString().split('T')[0])
          .order('snapshot_date');
      });

      // Ensure snapshots is an array
      const snapshotData = snapshots || [];

      // Transform snapshots into trend data
      const securityScores = snapshotData.map(s => ({
        date: s.snapshot_date,
        score: s.metrics.security_score || 0,
      }));

      const findingsTrends = snapshotData.map(s => ({
        date: s.snapshot_date,
        critical: s.metrics.findings_by_severity?.critical || 0,
        high: s.metrics.findings_by_severity?.high || 0,
        medium: s.metrics.findings_by_severity?.medium || 0,
        low: s.metrics.findings_by_severity?.low || 0,
        total: s.metrics.total_findings || 0,
      }));

      const scanActivity = snapshotData.map(s => ({
        date: s.snapshot_date,
        scansCount: s.metrics.scans_count || 0,
        averageScore: s.metrics.average_scan_score || 0,
      }));

      const resolutionTrends = snapshotData.map((s, index) => {
        const previousSnapshot = index > 0 ? snapshotData[index - 1] : null;
        const resolved = s.metrics.resolved_findings || 0;
        const opened = s.metrics.new_findings || 0;
        const previousResolved = previousSnapshot?.metrics.resolved_findings || 0;

        return {
          date: s.snapshot_date,
          resolved: resolved - previousResolved,
          opened,
          netChange: (resolved - previousResolved) - opened,
        };
      });

      return {
        securityScores,
        findingsTrends,
        scanActivity,
        resolutionTrends,
      };
    } catch (error) {
      this.logger.error(`Error generating security trends: ${error.message}`, error);
      throw error;
    }
  }

  async getComplianceScore(user: UserContext): Promise<ComplianceScoreDto> {
    try {
      // This would integrate with compliance frameworks
      // For now, return mock data based on findings analysis
      const findings = await this.getFindingsData(user.organizationId);
      
      const totalChecks = 100; // Mock total compliance checks
      const passedChecks = Math.max(0, totalChecks - findings.filter(f => f.status === 'open').length);
      const overallScore = Math.round((passedChecks / totalChecks) * 100);

      return {
        overallScore,
        byFramework: {
          'NIST': {
            score: overallScore + Math.floor(Math.random() * 10) - 5,
            passedChecks: Math.floor(passedChecks * 0.3),
            totalChecks: Math.floor(totalChecks * 0.3),
            criticalFailures: findings.filter(f => f.severity === 'critical').length,
          },
          'ISO 27001': {
            score: overallScore + Math.floor(Math.random() * 10) - 5,
            passedChecks: Math.floor(passedChecks * 0.4),
            totalChecks: Math.floor(totalChecks * 0.4),
            criticalFailures: findings.filter(f => f.severity === 'critical').length,
          },
          'CIS Controls': {
            score: overallScore + Math.floor(Math.random() * 10) - 5,
            passedChecks: Math.floor(passedChecks * 0.3),
            totalChecks: Math.floor(totalChecks * 0.3),
            criticalFailures: findings.filter(f => f.severity === 'critical').length,
          },
        },
        trends: [],
        topGaps: [],
      };
    } catch (error) {
      this.logger.error(`Error generating compliance score: ${error.message}`, error);
      throw error;
    }
  }

  private async getScansData(organizationId: string): Promise<any[]> {
    const result = await this.databaseService.executeQuery(async (client) => {
      return client
        .from('scans')
        .select('*')
        .eq('organization_id', organizationId)
        .eq('status', 'completed');
    });
    return result || [];
  }

  private async getFindingsData(organizationId: string): Promise<any[]> {
    const result = await this.databaseService.executeQuery(async (client) => {
      return client
        .from('findings')
        .select('*')
        .eq('organization_id', organizationId);
    });
    return result || [];
  }

  private async getRecentActivity(organizationId: string, days: number = 7): Promise<any> {
    const daysAgo = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    const [newFindings, resolvedFindings, scansCompleted] = await Promise.all([
      this.databaseService.executeQuery(async (client) => {
        return client
          .from('findings')
          .select('*')
          .eq('organization_id', organizationId)
          .gte('created_at', daysAgo.toISOString());
      }),
      this.databaseService.executeQuery(async (client) => {
        return client
          .from('findings')
          .select('*')
          .eq('organization_id', organizationId)
          .eq('status', 'resolved')
          .gte('resolved_at', daysAgo.toISOString());
      }),
      this.databaseService.executeQuery(async (client) => {
        return client
          .from('scans')
          .select('*')
          .eq('organization_id', organizationId)
          .eq('status', 'completed')
          .gte('completed_at', daysAgo.toISOString());
      }),
    ]);

    return {
      newFindings: (newFindings || []).length,
      resolvedFindings: (resolvedFindings || []).length,
      scansCompleted: (scansCompleted || []).length,
      daysRange: days,
    };
  }

  private getTopRiskCategories(findings: any[]): Array<any> {
    const categoryStats = findings.reduce((stats, finding) => {
      const category = finding.category || 'unknown';
      if (!stats[category]) {
        stats[category] = {
          category,
          count: 0,
          totalRisk: 0,
        };
      }
      stats[category].count++;
      stats[category].totalRisk += finding.risk_score || 0;
      return stats;
    }, {});

    return Object.values(categoryStats)
      .map((stat: any) => ({
        category: stat.category,
        count: stat.count,
        averageRiskScore: Math.round(stat.totalRisk / stat.count),
      }))
      .sort((a, b) => b.averageRiskScore - a.averageRiskScore)
      .slice(0, 5);
  }
}