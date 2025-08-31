// Generated types based on Supabase schema from Phase 1
export interface Database {
  public: {
    Tables: {
      organizations: {
        Row: {
          id: string
          name: string
          tier: 'community' | 'enterprise'
          settings: Record<string, any>
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          name: string
          tier?: 'community' | 'enterprise'
          settings?: Record<string, any>
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          name?: string
          tier?: 'community' | 'enterprise'
          settings?: Record<string, any>
          created_at?: string
          updated_at?: string
        }
      }
      user_profiles: {
        Row: {
          id: string
          email: string
          full_name: string | null
          avatar_url: string | null
          organization_id: string
          role: 'admin' | 'member' | 'viewer'
          created_at: string
          updated_at: string
        }
        Insert: {
          id: string
          email: string
          full_name?: string | null
          avatar_url?: string | null
          organization_id: string
          role?: 'admin' | 'member' | 'viewer'
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          email?: string
          full_name?: string | null
          avatar_url?: string | null
          organization_id?: string
          role?: 'admin' | 'member' | 'viewer'
          created_at?: string
          updated_at?: string
        }
      }
      scans: {
        Row: {
          id: string
          organization_id: string
          name: string
          status: 'pending' | 'running' | 'completed' | 'failed'
          score: number | null
          findings_count: number
          critical_count: number
          high_count: number
          medium_count: number
          low_count: number
          scan_metadata: Record<string, any>
          created_at: string
          completed_at: string | null
        }
        Insert: {
          id?: string
          organization_id: string
          name: string
          status?: 'pending' | 'running' | 'completed' | 'failed'
          score?: number | null
          findings_count?: number
          critical_count?: number
          high_count?: number
          medium_count?: number
          low_count?: number
          scan_metadata?: Record<string, any>
          created_at?: string
          completed_at?: string | null
        }
        Update: {
          id?: string
          organization_id?: string
          name?: string
          status?: 'pending' | 'running' | 'completed' | 'failed'
          score?: number | null
          findings_count?: number
          critical_count?: number
          high_count?: number
          medium_count?: number
          low_count?: number
          scan_metadata?: Record<string, any>
          created_at?: string
          completed_at?: string | null
        }
      }
      findings: {
        Row: {
          id: string
          scan_id: string
          check_id: string
          title: string
          description: string
          severity: 'Critical' | 'High' | 'Medium' | 'Low'
          category: string
          affected_objects: string[]
          remediation: string
          raw_data: Record<string, any>
          created_at: string
        }
        Insert: {
          id?: string
          scan_id: string
          check_id: string
          title: string
          description: string
          severity: 'Critical' | 'High' | 'Medium' | 'Low'
          category: string
          affected_objects: string[]
          remediation: string
          raw_data?: Record<string, any>
          created_at?: string
        }
        Update: {
          id?: string
          scan_id?: string
          check_id?: string
          title?: string
          description?: string
          severity?: 'Critical' | 'High' | 'Medium' | 'Low'
          category?: string
          affected_objects?: string[]
          remediation?: string
          raw_data?: Record<string, any>
          created_at?: string
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