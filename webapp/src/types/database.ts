// Generated types based on Supabase schema - Phase 4.2 Seeded Database
export interface Database {
  public: {
    Tables: {
      organizations: {
        Row: {
          id: string
          name: string
          slug: string
          tier: 'community' | 'enterprise' | 'easm'
          settings: Record<string, any>
          subscription_data: Record<string, any>
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          name: string
          slug: string
          tier?: 'community' | 'enterprise' | 'easm'
          settings?: Record<string, any>
          subscription_data?: Record<string, any>
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          name?: string
          slug?: string
          tier?: 'community' | 'enterprise' | 'easm'
          settings?: Record<string, any>
          subscription_data?: Record<string, any>
          created_at?: string
          updated_at?: string
        }
      }
      user_profiles: {
        Row: {
          id: string
          organization_id: string
          email: string
          full_name: string | null
          role: 'admin' | 'user' | 'viewer' | 'api_only'
          permissions: string[]
          last_login: string | null
          preferences: Record<string, any>
          created_at: string
          updated_at: string
        }
        Insert: {
          id: string
          organization_id?: string
          email: string
          full_name?: string | null
          role?: 'admin' | 'user' | 'viewer' | 'api_only'
          permissions?: string[]
          last_login?: string | null
          preferences?: Record<string, any>
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          email?: string
          full_name?: string | null
          role?: 'admin' | 'user' | 'viewer' | 'api_only'
          permissions?: string[]
          last_login?: string | null
          preferences?: Record<string, any>
          created_at?: string
          updated_at?: string
        }
      }
      scans: {
        Row: {
          id: string
          organization_id: string
          user_id: string | null
          name: string
          description: string | null
          scan_type: 'ad_only' | 'entra_only' | 'hybrid' | 'custom'
          status: 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled'
          raw_data: Record<string, any>
          processed_results: Record<string, any>
          metadata: Record<string, any>
          overall_score: number | null
          risk_level: 'critical' | 'high' | 'medium' | 'low' | 'info' | null
          findings_summary: Record<string, any>
          started_at: string | null
          completed_at: string | null
          processing_duration: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          user_id?: string | null
          name: string
          description?: string | null
          scan_type: 'ad_only' | 'entra_only' | 'hybrid' | 'custom'
          status?: 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled'
          raw_data: Record<string, any>
          processed_results?: Record<string, any>
          metadata?: Record<string, any>
          overall_score?: number | null
          risk_level?: 'critical' | 'high' | 'medium' | 'low' | 'info' | null
          findings_summary?: Record<string, any>
          started_at?: string | null
          completed_at?: string | null
          processing_duration?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          user_id?: string | null
          name?: string
          description?: string | null
          scan_type?: 'ad_only' | 'entra_only' | 'hybrid' | 'custom'
          status?: 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled'
          raw_data?: Record<string, any>
          processed_results?: Record<string, any>
          metadata?: Record<string, any>
          overall_score?: number | null
          risk_level?: 'critical' | 'high' | 'medium' | 'low' | 'info' | null
          findings_summary?: Record<string, any>
          started_at?: string | null
          completed_at?: string | null
          processing_duration?: string | null
          created_at?: string
          updated_at?: string
        }
      }
      findings: {
        Row: {
          id: string
          scan_id: string
          organization_id: string
          rule_id: string
          rule_name: string
          category: string
          severity: 'critical' | 'high' | 'medium' | 'low'
          title: string
          description: string
          affected_objects: Record<string, any>
          remediation: string | null
          external_references: Record<string, any>
          risk_score: number | null
          impact_score: number | null
          likelihood_score: number | null
          status: 'open' | 'in_progress' | 'resolved' | 'false_positive' | 'accepted_risk'
          assignee_id: string | null
          resolved_at: string | null
          resolution_notes: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          scan_id: string
          organization_id: string
          rule_id: string
          rule_name: string
          category: string
          severity: 'critical' | 'high' | 'medium' | 'low'
          title: string
          description: string
          affected_objects?: Record<string, any>
          remediation?: string | null
          external_references?: Record<string, any>
          risk_score?: number | null
          impact_score?: number | null
          likelihood_score?: number | null
          status?: 'open' | 'in_progress' | 'resolved' | 'false_positive' | 'accepted_risk'
          assignee_id?: string | null
          resolved_at?: string | null
          resolution_notes?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          scan_id?: string
          organization_id?: string
          rule_id?: string
          rule_name?: string
          category?: string
          severity?: 'critical' | 'high' | 'medium' | 'low'
          title?: string
          description?: string
          affected_objects?: Record<string, any>
          remediation?: string | null
          external_references?: Record<string, any>
          risk_score?: number | null
          impact_score?: number | null
          likelihood_score?: number | null
          status?: 'open' | 'in_progress' | 'resolved' | 'false_positive' | 'accepted_risk'
          assignee_id?: string | null
          resolved_at?: string | null
          resolution_notes?: string | null
          created_at?: string
          updated_at?: string
        }
      }
      analytics_snapshots: {
        Row: {
          id: string
          organization_id: string
          scan_id: string | null
          snapshot_date: string
          metrics: Record<string, any>
          trends: Record<string, any>
          created_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          scan_id?: string | null
          snapshot_date: string
          metrics: Record<string, any>
          trends?: Record<string, any>
          created_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          scan_id?: string | null
          snapshot_date?: string
          metrics?: Record<string, any>
          trends?: Record<string, any>
          created_at?: string
        }
      }
      api_keys: {
        Row: {
          id: string
          organization_id: string
          user_id: string
          name: string
          key_hash: string
          key_prefix: string
          permissions: string[]
          last_used_at: string | null
          expires_at: string | null
          is_active: boolean
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          user_id: string
          name: string
          key_hash: string
          key_prefix: string
          permissions?: string[]
          last_used_at?: string | null
          expires_at?: string | null
          is_active?: boolean
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          user_id?: string
          name?: string
          key_hash?: string
          key_prefix?: string
          permissions?: string[]
          last_used_at?: string | null
          expires_at?: string | null
          is_active?: boolean
          created_at?: string
          updated_at?: string
        }
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      calculate_organization_score: {
        Args: { org_id: string }
        Returns: number
      }
      get_scan_analytics: {
        Args: { org_id: string; days: number }
        Returns: Record<string, any>[]
      }
    }
    Enums: {
      [_ in never]: never
    }
  }
}

// Helper types
export type Organization = Database['public']['Tables']['organizations']['Row']
export type UserProfile = Database['public']['Tables']['user_profiles']['Row']
export type Scan = Database['public']['Tables']['scans']['Row']
export type Finding = Database['public']['Tables']['findings']['Row']
export type AnalyticsSnapshot = Database['public']['Tables']['analytics_snapshots']['Row']
export type ApiKey = Database['public']['Tables']['api_keys']['Row']

// Enhanced types for dashboard
export type ScanWithFindings = Scan & {
  findings?: Finding[]
  findingsCount?: number
}

export type UserProfileWithOrganization = UserProfile & {
  organizations?: Organization
}

// Dashboard summary interface
export interface DashboardSummary {
  totalScans: number
  activeFindings: number
  criticalFindings: number
  highSeverityFindings: number
  overallSecurityScore: number | null
  scoreTrend: number
}