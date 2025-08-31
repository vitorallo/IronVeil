import { ApiProperty } from '@nestjs/swagger';

export class DashboardSummaryDto {
  @ApiProperty({ description: 'Total number of scans' })
  totalScans: number;

  @ApiProperty({ description: 'Total number of findings' })
  totalFindings: number;

  @ApiProperty({ description: 'Number of active findings' })
  activeFindings: number;

  @ApiProperty({ description: 'Number of resolved findings' })
  resolvedFindings: number;

  @ApiProperty({ description: 'Overall security score (0-100)' })
  overallSecurityScore: number;

  @ApiProperty({ description: 'Security score trend (positive/negative)' })
  scoreTrend: number;

  @ApiProperty({ description: 'Critical findings count' })
  criticalFindings: number;

  @ApiProperty({ description: 'High severity findings count' })
  highSeverityFindings: number;

  @ApiProperty({ description: 'Last scan date' })
  lastScanDate?: string;

  @ApiProperty({ description: 'Scan frequency (scans per month)' })
  scanFrequency: number;

  @ApiProperty({ description: 'Top risk categories' })
  topRiskCategories: Array<{
    category: string;
    count: number;
    averageRiskScore: number;
  }>;

  @ApiProperty({ description: 'Recent activity summary' })
  recentActivity: {
    newFindings: number;
    resolvedFindings: number;
    scansCompleted: number;
    daysRange: number;
  };
}

export class SecurityTrendsDto {
  @ApiProperty({ description: 'Security score over time' })
  securityScores: Array<{
    date: string;
    score: number;
  }>;

  @ApiProperty({ description: 'Findings count over time' })
  findingsTrends: Array<{
    date: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  }>;

  @ApiProperty({ description: 'Scan activity over time' })
  scanActivity: Array<{
    date: string;
    scansCount: number;
    averageScore: number;
  }>;

  @ApiProperty({ description: 'Resolution trends' })
  resolutionTrends: Array<{
    date: string;
    resolved: number;
    opened: number;
    netChange: number;
  }>;
}

export class ComplianceScoreDto {
  @ApiProperty({ description: 'Overall compliance percentage' })
  overallScore: number;

  @ApiProperty({ description: 'Compliance by framework' })
  byFramework: Record<string, {
    score: number;
    passedChecks: number;
    totalChecks: number;
    criticalFailures: number;
  }>;

  @ApiProperty({ description: 'Compliance trends over time' })
  trends: Array<{
    date: string;
    score: number;
  }>;

  @ApiProperty({ description: 'Top compliance gaps' })
  topGaps: Array<{
    framework: string;
    category: string;
    failedChecks: number;
    riskLevel: string;
  }>;
}