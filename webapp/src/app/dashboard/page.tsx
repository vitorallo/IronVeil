'use client'

import { createClient } from '@/lib/supabase/client'
import { DashboardLayout } from '@/components/dashboard/layout'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Skeleton } from '@/components/ui/skeleton'
import { Shield, Users, AlertTriangle, CheckCircle, TrendingUp, TrendingDown } from 'lucide-react'
import { useRouter } from 'next/navigation'
import { useEffect, useState } from 'react'
import { useDashboardData } from '@/hooks/use-dashboard-data'

interface UserProfile {
  id: string;
  email: string;
  full_name: string;
  organization_id: string;
  role: string;
  organizations?: {
    id: string;
    name: string;
    tier: string;
  };
}

export default function DashboardPage() {
  const router = useRouter()
  const [user, setUser] = useState<any>(null)
  const [authLoading, setAuthLoading] = useState(true)
  const { summary, recentScans, userProfile, loading: dataLoading, error } = useDashboardData()

  useEffect(() => {
    const checkAuth = async () => {
      const supabase = createClient()
      const { data: { user } } = await supabase.auth.getUser()
      
      if (!user) {
        router.push('/login')
        return
      }

      setUser(user)
      setAuthLoading(false)
    }

    checkAuth()
  }, [router])

  // Show loading state while authenticating or loading data
  if (authLoading || dataLoading) {
    return (
      <div className="min-h-screen bg-background">
        <DashboardLayout user={null} userProfile={null}>
          <div className="space-y-8 mb-8">
            <div className="space-y-4">
              <Skeleton className="h-10 w-48" />
              <Skeleton className="h-6 w-96" />
            </div>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              {Array.from({ length: 4 }).map((_, i) => (
                <Card key={i}>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <Skeleton className="h-4 w-24" />
                    <Skeleton className="h-4 w-4" />
                  </CardHeader>
                  <CardContent>
                    <Skeleton className="h-8 w-12 mb-2" />
                    <Skeleton className="h-3 w-20" />
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </DashboardLayout>
      </div>
    )
  }

  // Calculate derived stats from API data
  const totalScans = summary?.totalScans || 0
  const activeIssues = summary?.activeFindings || 0 
  const criticalFindings = summary?.criticalFindings || 0
  const highFindings = summary?.highSeverityFindings || 0
  const overallScore = summary?.overallSecurityScore || null
  const scoreTrend = summary?.scoreTrend || 0
  
  // Determine trend direction
  const securityTrend = scoreTrend > 0 ? 'up' : scoreTrend < 0 ? 'down' : 'stable'

  return (
    <DashboardLayout user={user} userProfile={userProfile}>
      <div className="space-y-8 mb-8">
        {/* Header */}
        <div className="space-y-1">
          <h1 className="text-4xl font-bold text-foreground tracking-tight">
            Dashboard
          </h1>
          <p className="text-lg text-muted-foreground font-medium">
            Welcome back, <span className="text-primary font-semibold">{userProfile?.full_name || user?.email?.split('@')[0] || 'User'}</span>. 
            Here's your security overview.
          </p>
        </div>

        {/* Summary Cards */}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Card className="card-hover interactive-glow">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
              <Shield className="h-4 w-4 text-primary interactive-scale" />
            </CardHeader>
            <CardContent>
              {dataLoading ? (
                <>
                  <Skeleton className="h-8 w-12 mb-2" />
                  <Skeleton className="h-3 w-20" />
                </>
              ) : error ? (
                <>
                  <div className="text-2xl font-bold text-muted-foreground">--</div>
                  <p className="text-xs text-destructive">Error loading</p>
                </>
              ) : (
                <>
                  <div className="text-2xl font-bold text-foreground">{totalScans}</div>
                  <p className="text-xs text-muted-foreground">
                    {recentScans.filter(scan => scan.status === 'completed').length} completed
                  </p>
                </>
              )}
            </CardContent>
          </Card>

          <Card className="card-hover interactive-glow">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Active Issues</CardTitle>
              <AlertTriangle className={`h-4 w-4 interactive-scale ${
                criticalFindings > 0 ? 'text-destructive status-pulse' : 'text-warning'
              }`} />
            </CardHeader>
            <CardContent>
              {dataLoading ? (
                <>
                  <Skeleton className="h-8 w-12 mb-2" />
                  <Skeleton className="h-3 w-20" />
                </>
              ) : error ? (
                <>
                  <div className="text-2xl font-bold text-muted-foreground">--</div>
                  <p className="text-xs text-destructive">Error loading</p>
                </>
              ) : (
                <>
                  <div className={`text-2xl font-bold ${criticalFindings > 0 ? 'text-destructive' : 'text-foreground'}`}>
                    {activeIssues}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    <span className={criticalFindings > 0 ? 'text-destructive font-medium status-pulse' : ''}>
                      {criticalFindings} critical, {highFindings} high
                    </span>
                  </p>
                </>
              )}
            </CardContent>
          </Card>

          <Card className="card-hover interactive-glow">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Organization</CardTitle>
              <Users className="h-4 w-4 text-accent interactive-scale" />
            </CardHeader>
            <CardContent>
              {authLoading || dataLoading ? (
                <>
                  <Skeleton className="h-8 w-32 mb-2" />
                  <Skeleton className="h-4 w-20" />
                </>
              ) : (
                <>
                  <div className="text-2xl font-bold text-foreground">{userProfile?.organizations?.name || 'Unknown'}</div>
                  <Badge className="text-xs mt-1 interactive-fade" variant="secondary">
                    {userProfile?.organizations?.tier || 'community'}
                  </Badge>
                </>
              )}
            </CardContent>
          </Card>

          <Card className="card-hover interactive-glow">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Security Score</CardTitle>
              <div className="flex items-center space-x-1">
                {securityTrend === 'up' && <TrendingUp className="h-4 w-4 text-success trend-up interactive-scale" />}
                {securityTrend === 'down' && <TrendingDown className="h-4 w-4 text-destructive trend-down interactive-scale" />}
                {securityTrend === 'stable' && <CheckCircle className="h-4 w-4 text-info interactive-scale" />}
                {!overallScore && <CheckCircle className="h-4 w-4 text-muted-foreground interactive-scale" />}
              </div>
            </CardHeader>
            <CardContent>
              {dataLoading ? (
                <>
                  <Skeleton className="h-8 w-16 mb-2" />
                  <Skeleton className="h-2 w-full mb-1" />
                  <Skeleton className="h-3 w-24" />
                </>
              ) : error ? (
                <>
                  <div className="text-2xl font-bold text-muted-foreground">--</div>
                  <p className="text-xs text-destructive">Error loading</p>
                </>
              ) : (
                <>
                  <div className={`text-2xl font-bold ${
                    overallScore ? (
                      overallScore >= 80 ? 'text-success' :
                      overallScore >= 60 ? 'text-info' :
                      overallScore >= 40 ? 'text-warning' :
                      'text-destructive'
                    ) : 'text-muted-foreground'
                  }`}>
                    {overallScore || '--'}
                    {overallScore && '/100'}
                  </div>
                  {overallScore ? (
                    <div className="mt-2">
                      <Progress 
                        value={overallScore} 
                        className="h-2 progress-animate"
                      />
                      <p className="text-xs text-muted-foreground mt-1">
                        {securityTrend === 'up' && '↗ Improving'}
                        {securityTrend === 'down' && '↘ Needs attention'}
                        {securityTrend === 'stable' && '→ Stable'}
                      </p>
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground">
                      Run a scan to get score
                    </p>
                  )}
                </>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Recent Scans */}
        <Card className="card-hover">
          <CardHeader>
            <CardTitle className="text-lg font-semibold">Recent Scans</CardTitle>
          </CardHeader>
          <CardContent>
            {dataLoading ? (
              <div className="space-y-4">
                {Array.from({ length: 3 }).map((_, i) => (
                  <div key={i} className="flex items-center justify-between p-4 border rounded-lg">
                    <div>
                      <Skeleton className="h-5 w-48 mb-2" />
                      <Skeleton className="h-4 w-32" />
                    </div>
                    <div className="flex items-center space-x-2">
                      <Skeleton className="h-6 w-20" />
                      <Skeleton className="h-6 w-12" />
                    </div>
                  </div>
                ))}
              </div>
            ) : error ? (
              <div className="text-center py-12">
                <AlertTriangle className="h-16 w-16 text-destructive mx-auto mb-6" />
                <h3 className="text-2xl font-bold text-foreground mb-3">Error loading scans</h3>
                <p className="text-lg text-muted-foreground mb-6">
                  {error}
                </p>
              </div>
            ) : recentScans && recentScans.length > 0 ? (
              <div className="space-y-4">
                {recentScans.map((scan) => {
                  // Calculate total findings from findings summary if available
                  const findingsCount = scan.findings_summary?.total || 
                    Object.values(scan.findings_summary || {}).reduce((sum, count) => 
                      typeof count === 'number' ? sum + count : sum, 0
                    ) || 0;

                  return (
                    <div key={scan.id} className="flex items-center justify-between p-4 border rounded-lg card-hover interactive-glow focus-ring" tabIndex={0}>
                      <div>
                        <h3 className="font-semibold text-foreground">{scan.name}</h3>
                        <p className="text-sm text-muted-foreground">
                          {new Date(scan.created_at).toLocaleDateString()} • 
                          <span className="font-medium">{findingsCount} findings</span>
                        </p>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge 
                          variant={scan.status === 'completed' ? 'default' : 'secondary'}
                          className={`interactive-scale ${
                            scan.status === 'completed' ? 'bg-success text-success-foreground' :
                            scan.status === 'failed' ? 'bg-destructive text-destructive-foreground' :
                            scan.status === 'processing' ? 'bg-info text-info-foreground status-pulse' :
                            'bg-secondary text-secondary-foreground'
                          }`}
                        >
                          {scan.status}
                        </Badge>
                        {scan.overall_score && (
                          <div className={`text-lg font-bold interactive-scale ${
                            scan.overall_score >= 80 ? 'text-success' :
                            scan.overall_score >= 60 ? 'text-info' :
                            scan.overall_score >= 40 ? 'text-warning' :
                            'text-destructive'
                          }`}>
                            {Math.round(scan.overall_score)}/100
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-center py-12">
                <Shield className="h-16 w-16 text-muted-foreground mx-auto mb-6 interactive-scale" />
                <h3 className="text-2xl font-bold text-foreground mb-3">No scans yet</h3>
                <p className="text-lg text-muted-foreground mb-6 max-w-md mx-auto">
                  Get started by running your first security scan using the IronVeil desktop scanner.
                </p>
                <div className="bg-primary/5 border border-primary/20 p-6 rounded-xl text-primary max-w-lg mx-auto">
                  <h4 className="font-bold text-lg mb-3">Next steps:</h4>
                  <ol className="text-left list-decimal list-inside space-y-2 font-medium">
                    <li>Download the IronVeil desktop scanner</li>
                    <li>Run it on your Active Directory or Entra ID environment</li>
                    <li>View results here in real-time</li>
                  </ol>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  )
}