import { createClient } from '@/lib/supabase/server'
import { DashboardLayout } from '@/components/dashboard/layout'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Shield, Users, AlertTriangle, CheckCircle, TrendingUp, TrendingDown } from 'lucide-react'
import { redirect } from 'next/navigation'

export default async function DashboardPage() {
  const supabase = await createClient()
  
  const { data: { user } } = await supabase.auth.getUser()
  
  if (!user) {
    redirect('/login')
  }

  // Fetch user profile and organization
  const { data: userProfile } = await supabase
    .from('user_profiles')
    .select(`
      *,
      organizations (
        id,
        name,
        tier
      )
    `)
    .eq('id', user.id)
    .single()

  // Fetch recent scans for the organization
  const { data: recentScans } = await supabase
    .from('scans')
    .select('*')
    .eq('organization_id', userProfile?.organization_id)
    .order('created_at', { ascending: false })
    .limit(5)

  // Calculate summary stats
  const totalScans = recentScans?.length || 0
  const completedScans = recentScans?.filter(scan => scan.status === 'completed').length || 0
  const totalFindings = recentScans?.reduce((sum, scan) => sum + scan.findings_count, 0) || 0
  const criticalFindings = recentScans?.reduce((sum, scan) => sum + scan.critical_count, 0) || 0
  
  // Calculate security score and trends
  const avgScore = recentScans?.length > 0 
    ? Math.round(recentScans.filter(scan => scan.overall_score).reduce((sum, scan) => sum + scan.overall_score, 0) / recentScans.filter(scan => scan.overall_score).length)
    : null
  
  // Mock trend data - in real implementation, this would come from historical data
  const securityTrend = avgScore ? (avgScore > 75 ? 'up' : avgScore > 50 ? 'stable' : 'down') : null

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
              <div className="text-2xl font-bold text-foreground">{totalScans}</div>
              <p className="text-xs text-muted-foreground">
                {completedScans} completed
              </p>
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
              <div className={`text-2xl font-bold ${criticalFindings > 0 ? 'text-destructive' : 'text-foreground'}`}>
                {totalFindings}
              </div>
              <p className="text-xs text-muted-foreground">
                <span className={criticalFindings > 0 ? 'text-destructive font-medium status-pulse' : ''}>
                  {criticalFindings} critical
                </span>
              </p>
            </CardContent>
          </Card>

          <Card className="card-hover interactive-glow">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Organization</CardTitle>
              <Users className="h-4 w-4 text-accent interactive-scale" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-foreground">{userProfile?.organizations?.name}</div>
              <Badge className="text-xs mt-1 interactive-fade" variant="secondary">
                {userProfile?.organizations?.tier}
              </Badge>
            </CardContent>
          </Card>

          <Card className="card-hover interactive-glow">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Security Score</CardTitle>
              <div className="flex items-center space-x-1">
                {securityTrend === 'up' && <TrendingUp className="h-4 w-4 text-success trend-up interactive-scale" />}
                {securityTrend === 'down' && <TrendingDown className="h-4 w-4 text-destructive trend-down interactive-scale" />}
                {securityTrend === 'stable' && <CheckCircle className="h-4 w-4 text-info interactive-scale" />}
                {!securityTrend && <CheckCircle className="h-4 w-4 text-muted-foreground interactive-scale" />}
              </div>
            </CardHeader>
            <CardContent>
              <div className={`text-2xl font-bold ${
                avgScore ? (
                  avgScore >= 80 ? 'text-success' :
                  avgScore >= 60 ? 'text-info' :
                  avgScore >= 40 ? 'text-warning' :
                  'text-destructive'
                ) : 'text-muted-foreground'
              }`}>
                {avgScore || '--'}
                {avgScore && '/100'}
              </div>
              {avgScore ? (
                <div className="mt-2">
                  <Progress 
                    value={avgScore} 
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
            </CardContent>
          </Card>
        </div>

        {/* Recent Scans */}
        <Card className="card-hover">
          <CardHeader>
            <CardTitle className="text-lg font-semibold">Recent Scans</CardTitle>
          </CardHeader>
          <CardContent>
            {recentScans && recentScans.length > 0 ? (
              <div className="space-y-4">
                {recentScans.map((scan) => (
                  <div key={scan.id} className="flex items-center justify-between p-4 border rounded-lg card-hover interactive-glow focus-ring" tabIndex={0}>
                    <div>
                      <h3 className="font-semibold text-foreground">{scan.name}</h3>
                      <p className="text-sm text-muted-foreground">
                        {new Date(scan.created_at).toLocaleDateString()} • 
                        <span className="font-medium">{scan.findings_count} findings</span>
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
                      {scan.score && (
                        <div className={`text-lg font-bold interactive-scale ${
                          scan.score >= 80 ? 'text-success' :
                          scan.score >= 60 ? 'text-info' :
                          scan.score >= 40 ? 'text-warning' :
                          'text-destructive'
                        }`}>
                          {scan.score}/100
                        </div>
                      )}
                    </div>
                  </div>
                ))}
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