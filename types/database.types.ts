export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  graphql_public: {
    Tables: {
      [_ in never]: never
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      graphql: {
        Args: {
          extensions?: Json
          operationName?: string
          query?: string
          variables?: Json
        }
        Returns: Json
      }
    }
    Enums: {
      [_ in never]: never
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
  public: {
    Tables: {
      analytics_snapshots: {
        Row: {
          created_at: string | null
          id: string
          metrics: Json
          organization_id: string
          scan_id: string | null
          snapshot_date: string
          trends: Json | null
        }
        Insert: {
          created_at?: string | null
          id?: string
          metrics: Json
          organization_id: string
          scan_id?: string | null
          snapshot_date: string
          trends?: Json | null
        }
        Update: {
          created_at?: string | null
          id?: string
          metrics?: Json
          organization_id?: string
          scan_id?: string | null
          snapshot_date?: string
          trends?: Json | null
        }
        Relationships: [
          {
            foreignKeyName: "analytics_snapshots_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "analytics_snapshots_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["id"]
          },
        ]
      }
      api_keys: {
        Row: {
          created_at: string | null
          expires_at: string | null
          id: string
          is_active: boolean | null
          key_hash: string
          key_prefix: string
          last_used_at: string | null
          name: string
          organization_id: string
          permissions: string[] | null
          updated_at: string | null
          user_id: string
        }
        Insert: {
          created_at?: string | null
          expires_at?: string | null
          id?: string
          is_active?: boolean | null
          key_hash: string
          key_prefix: string
          last_used_at?: string | null
          name: string
          organization_id: string
          permissions?: string[] | null
          updated_at?: string | null
          user_id: string
        }
        Update: {
          created_at?: string | null
          expires_at?: string | null
          id?: string
          is_active?: boolean | null
          key_hash?: string
          key_prefix?: string
          last_used_at?: string | null
          name?: string
          organization_id?: string
          permissions?: string[] | null
          updated_at?: string | null
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "api_keys_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "api_keys_user_id_fkey"
            columns: ["user_id"]
            isOneToOne: false
            referencedRelation: "user_profiles"
            referencedColumns: ["id"]
          },
        ]
      }
      findings: {
        Row: {
          affected_objects: Json | null
          assignee_id: string | null
          category: string
          created_at: string | null
          description: string
          external_references: Json | null
          id: string
          impact_score: number | null
          likelihood_score: number | null
          organization_id: string
          remediation: string | null
          resolution_notes: string | null
          resolved_at: string | null
          risk_score: number | null
          rule_id: string
          rule_name: string
          scan_id: string
          severity: Database["public"]["Enums"]["severity_enum"]
          status: Database["public"]["Enums"]["finding_status_enum"] | null
          title: string
          updated_at: string | null
        }
        Insert: {
          affected_objects?: Json | null
          assignee_id?: string | null
          category: string
          created_at?: string | null
          description: string
          external_references?: Json | null
          id?: string
          impact_score?: number | null
          likelihood_score?: number | null
          organization_id: string
          remediation?: string | null
          resolution_notes?: string | null
          resolved_at?: string | null
          risk_score?: number | null
          rule_id: string
          rule_name: string
          scan_id: string
          severity: Database["public"]["Enums"]["severity_enum"]
          status?: Database["public"]["Enums"]["finding_status_enum"] | null
          title: string
          updated_at?: string | null
        }
        Update: {
          affected_objects?: Json | null
          assignee_id?: string | null
          category?: string
          created_at?: string | null
          description?: string
          external_references?: Json | null
          id?: string
          impact_score?: number | null
          likelihood_score?: number | null
          organization_id?: string
          remediation?: string | null
          resolution_notes?: string | null
          resolved_at?: string | null
          risk_score?: number | null
          rule_id?: string
          rule_name?: string
          scan_id?: string
          severity?: Database["public"]["Enums"]["severity_enum"]
          status?: Database["public"]["Enums"]["finding_status_enum"] | null
          title?: string
          updated_at?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "findings_assignee_id_fkey"
            columns: ["assignee_id"]
            isOneToOne: false
            referencedRelation: "user_profiles"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "findings_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "findings_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["id"]
          },
        ]
      }
      organizations: {
        Row: {
          created_at: string | null
          id: string
          name: string
          settings: Json | null
          slug: string
          subscription_data: Json | null
          tier: Database["public"]["Enums"]["tier_enum"]
          updated_at: string | null
        }
        Insert: {
          created_at?: string | null
          id?: string
          name: string
          settings?: Json | null
          slug: string
          subscription_data?: Json | null
          tier?: Database["public"]["Enums"]["tier_enum"]
          updated_at?: string | null
        }
        Update: {
          created_at?: string | null
          id?: string
          name?: string
          settings?: Json | null
          slug?: string
          subscription_data?: Json | null
          tier?: Database["public"]["Enums"]["tier_enum"]
          updated_at?: string | null
        }
        Relationships: []
      }
      scans: {
        Row: {
          completed_at: string | null
          created_at: string | null
          description: string | null
          findings_summary: Json | null
          id: string
          metadata: Json | null
          name: string
          organization_id: string
          overall_score: number | null
          processed_results: Json | null
          processing_duration: unknown | null
          raw_data: Json
          risk_level: Database["public"]["Enums"]["risk_level_enum"] | null
          scan_type: Database["public"]["Enums"]["scan_type_enum"]
          started_at: string | null
          status: Database["public"]["Enums"]["scan_status_enum"]
          updated_at: string | null
          user_id: string | null
        }
        Insert: {
          completed_at?: string | null
          created_at?: string | null
          description?: string | null
          findings_summary?: Json | null
          id?: string
          metadata?: Json | null
          name: string
          organization_id: string
          overall_score?: number | null
          processed_results?: Json | null
          processing_duration?: unknown | null
          raw_data: Json
          risk_level?: Database["public"]["Enums"]["risk_level_enum"] | null
          scan_type: Database["public"]["Enums"]["scan_type_enum"]
          started_at?: string | null
          status?: Database["public"]["Enums"]["scan_status_enum"]
          updated_at?: string | null
          user_id?: string | null
        }
        Update: {
          completed_at?: string | null
          created_at?: string | null
          description?: string | null
          findings_summary?: Json | null
          id?: string
          metadata?: Json | null
          name?: string
          organization_id?: string
          overall_score?: number | null
          processed_results?: Json | null
          processing_duration?: unknown | null
          raw_data?: Json
          risk_level?: Database["public"]["Enums"]["risk_level_enum"] | null
          scan_type?: Database["public"]["Enums"]["scan_type_enum"]
          started_at?: string | null
          status?: Database["public"]["Enums"]["scan_status_enum"]
          updated_at?: string | null
          user_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "scans_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "scans_user_id_fkey"
            columns: ["user_id"]
            isOneToOne: false
            referencedRelation: "user_profiles"
            referencedColumns: ["id"]
          },
        ]
      }
      user_profiles: {
        Row: {
          created_at: string | null
          email: string
          full_name: string | null
          id: string
          last_login: string | null
          organization_id: string | null
          permissions: string[] | null
          preferences: Json | null
          role: Database["public"]["Enums"]["user_role_enum"]
          updated_at: string | null
        }
        Insert: {
          created_at?: string | null
          email: string
          full_name?: string | null
          id: string
          last_login?: string | null
          organization_id?: string | null
          permissions?: string[] | null
          preferences?: Json | null
          role?: Database["public"]["Enums"]["user_role_enum"]
          updated_at?: string | null
        }
        Update: {
          created_at?: string | null
          email?: string
          full_name?: string | null
          id?: string
          last_login?: string | null
          organization_id?: string | null
          permissions?: string[] | null
          preferences?: Json | null
          role?: Database["public"]["Enums"]["user_role_enum"]
          updated_at?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "user_profiles_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
    }
    Views: {
      dashboard_metrics: {
        Row: {
          avg_security_score: number | null
          critical_findings: number | null
          high_findings: number | null
          last_scan_date: string | null
          low_findings: number | null
          medium_findings: number | null
          organization_id: string | null
          recent_scans: number | null
          resolved_findings: number | null
          total_scans: number | null
        }
        Relationships: [
          {
            foreignKeyName: "scans_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
    }
    Functions: {
      calculate_finding_risk_score: {
        Args: {
          affected_object_count?: number
          impact_score?: number
          likelihood_score?: number
          severity_level: Database["public"]["Enums"]["severity_enum"]
        }
        Returns: number
      }
      calculate_org_security_score: {
        Args: { days_back?: number; org_id: string }
        Returns: number
      }
      create_audit_log: {
        Args: {
          action: string
          new_data?: Json
          old_data?: Json
          record_id: string
          table_name: string
          user_id?: string
        }
        Returns: undefined
      }
      get_findings_trend: {
        Args: { days_back?: number; org_id: string }
        Returns: {
          critical_count: number
          date: string
          high_count: number
          low_count: number
          medium_count: number
        }[]
      }
      get_organization_dashboard_summary: {
        Args: { org_id: string }
        Returns: Json
      }
      get_scan_statistics: {
        Args: { days_back?: number; org_id: string }
        Returns: Json
      }
      get_user_organization_id: {
        Args: Record<PropertyKey, never>
        Returns: string
      }
      get_user_role: {
        Args: Record<PropertyKey, never>
        Returns: Database["public"]["Enums"]["user_role_enum"]
      }
      process_desktop_scan: {
        Args: {
          p_org_id: string
          p_scan_data: Json
          p_scan_name: string
          p_scan_type: Database["public"]["Enums"]["scan_type_enum"]
          p_user_id: string
        }
        Returns: string
      }
      refresh_dashboard_metrics: {
        Args: Record<PropertyKey, never>
        Returns: undefined
      }
    }
    Enums: {
      finding_status_enum:
        | "open"
        | "in_progress"
        | "resolved"
        | "false_positive"
        | "accepted_risk"
      risk_level_enum: "critical" | "high" | "medium" | "low" | "info"
      scan_status_enum:
        | "pending"
        | "processing"
        | "completed"
        | "failed"
        | "cancelled"
      scan_type_enum: "ad_only" | "entra_only" | "hybrid" | "custom"
      severity_enum: "critical" | "high" | "medium" | "low"
      tier_enum: "community" | "enterprise" | "easm"
      user_role_enum: "admin" | "user" | "viewer" | "api_only"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  graphql_public: {
    Enums: {},
  },
  public: {
    Enums: {
      finding_status_enum: [
        "open",
        "in_progress",
        "resolved",
        "false_positive",
        "accepted_risk",
      ],
      risk_level_enum: ["critical", "high", "medium", "low", "info"],
      scan_status_enum: [
        "pending",
        "processing",
        "completed",
        "failed",
        "cancelled",
      ],
      scan_type_enum: ["ad_only", "entra_only", "hybrid", "custom"],
      severity_enum: ["critical", "high", "medium", "low"],
      tier_enum: ["community", "enterprise", "easm"],
      user_role_enum: ["admin", "user", "viewer", "api_only"],
    },
  },
} as const

