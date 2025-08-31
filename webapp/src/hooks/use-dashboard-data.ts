'use client'

import { useState, useEffect, useRef } from 'react'
import { createClient } from '@/lib/supabase/client'
import type { DashboardSummary, Scan, Finding, UserProfileWithOrganization } from '@/types/database'

interface DashboardData {
  summary: DashboardSummary | null
  recentScans: Scan[]
  loading: boolean
  error: string | null
  userProfile: UserProfileWithOrganization | null
}

export function useDashboardData(): DashboardData {
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [recentScans, setRecentScans] = useState<Scan[]>([])
  const [userProfile, setUserProfile] = useState<UserProfileWithOrganization | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  
  const subscriptionRef = useRef<any>(null)
  const supabase = createClient()

  useEffect(() => {
    let ignore = false
    
    const fetchDashboardData = async () => {
      try {
        setLoading(true)
        setError(null)

        // Get current authenticated user
        const { data: { user }, error: authError } = await supabase.auth.getUser()
        
        if (authError || !user) {
          throw new Error('Authentication required')
        }

        // Fetch user profile with organization
        const { data: profile, error: profileError } = await supabase
          .from('user_profiles')
          .select(`
            *,
            organizations (
              id,
              name,
              tier,
              slug
            )
          `)
          .eq('id', user.id)
          .single()

        if (profileError) {
          throw new Error(`Failed to fetch user profile: ${profileError.message}`)
        }

        if (!profile?.organization_id) {
          throw new Error('User is not associated with an organization')
        }

        const organizationId = profile.organization_id

        // Fetch dashboard data in parallel using direct Supabase queries
        const [scansResponse, findingsResponse] = await Promise.all([
          // Get recent scans for the organization
          supabase
            .from('scans')
            .select('*')
            .eq('organization_id', organizationId)
            .order('created_at', { ascending: false })
            .limit(5),
          
          // Get active findings for the organization
          supabase
            .from('findings')
            .select('*')
            .eq('organization_id', organizationId)
            .in('status', ['open', 'in_progress'])
        ])

        if (scansResponse.error) {
          throw new Error(`Failed to fetch scans: ${scansResponse.error.message}`)
        }

        if (findingsResponse.error) {
          throw new Error(`Failed to fetch findings: ${findingsResponse.error.message}`)
        }

        const scans = scansResponse.data || []
        const activeFindings = findingsResponse.data || []

        // Calculate summary statistics
        const totalScans = scans.length
        const criticalFindings = activeFindings.filter(f => f.severity === 'critical').length
        const highFindings = activeFindings.filter(f => f.severity === 'high').length
        
        // Calculate overall security score (average of completed scans)
        const completedScans = scans.filter(s => s.status === 'completed' && s.overall_score !== null)
        const overallSecurityScore = completedScans.length > 0 
          ? Math.round(completedScans.reduce((sum, s) => sum + (s.overall_score || 0), 0) / completedScans.length)
          : null

        // Calculate score trend (simplified - comparing latest vs average)
        let scoreTrend = 0
        if (completedScans.length > 1) {
          const latestScore = completedScans[0]?.overall_score || 0
          const previousAverage = completedScans.slice(1).reduce((sum, s) => sum + (s.overall_score || 0), 0) / (completedScans.length - 1)
          scoreTrend = latestScore - previousAverage
        }

        if (!ignore) {
          setUserProfile(profile as UserProfileWithOrganization)
          setRecentScans(scans)
          setSummary({
            totalScans,
            activeFindings: activeFindings.length,
            criticalFindings,
            highSeverityFindings: highFindings,
            overallSecurityScore,
            scoreTrend
          })

          // Set up real-time subscriptions for live updates
          setupRealtimeSubscriptions(organizationId)
        }
      } catch (err) {
        if (!ignore) {
          const errorMessage = err instanceof Error ? err.message : 'Failed to fetch dashboard data'
          setError(errorMessage)
          console.error('Dashboard data fetch error:', err)
        }
      } finally {
        if (!ignore) {
          setLoading(false)
        }
      }
    }

    const setupRealtimeSubscriptions = (organizationId: string) => {
      // Clean up existing subscription
      if (subscriptionRef.current) {
        subscriptionRef.current.unsubscribe()
      }

      // Subscribe to real-time changes for scans and findings
      subscriptionRef.current = supabase
        .channel('dashboard-updates')
        .on(
          'postgres_changes',
          {
            event: '*',
            schema: 'public',
            table: 'scans',
            filter: `organization_id=eq.${organizationId}`
          },
          (payload) => {
            console.log('Real-time scan update:', payload)
            // Refresh data when scans change
            fetchDashboardData()
          }
        )
        .on(
          'postgres_changes',
          {
            event: '*',
            schema: 'public',
            table: 'findings',
            filter: `organization_id=eq.${organizationId}`
          },
          (payload) => {
            console.log('Real-time finding update:', payload)
            // Refresh data when findings change
            fetchDashboardData()
          }
        )
        .subscribe()
    }

    fetchDashboardData()

    return () => {
      ignore = true
      if (subscriptionRef.current) {
        subscriptionRef.current.unsubscribe()
      }
    }
  }, [])

  return {
    summary,
    recentScans,
    userProfile,
    loading,
    error
  }
}