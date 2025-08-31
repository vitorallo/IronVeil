/**
 * API Client for IronVeil Backend Integration
 * 
 * This client handles all communication with the NestJS backend API,
 * including JWT authentication, error handling, and type-safe responses.
 */

import { createClient } from '@/lib/supabase/client';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:3001/api';

interface ApiResponse<T = any> {
  data?: T;
  error?: string;
  message?: string;
}

interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

// Dashboard Summary Types
interface DashboardSummary {
  totalScans: number;
  totalFindings: number;
  activeFindings: number;
  resolvedFindings: number;
  overallSecurityScore: number;
  scoreTrend: number;
  criticalFindings: number;
  highSeverityFindings: number;
  lastScanDate?: string;
  scanFrequency: number;
  topRiskCategories: Array<{
    category: string;
    count: number;
    averageRiskScore: number;
  }>;
  recentActivity: {
    newFindings: number;
    resolvedFindings: number;
    scansCompleted: number;
    daysRange: number;
  };
}

// Scan Types
interface Scan {
  id: string;
  name: string;
  scanType: 'ad_only' | 'entra_only' | 'hybrid' | 'custom';
  status: 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled';
  overallScore?: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  findingsSummary: Record<string, any>;
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
  organizationId: string;
  userId: string;
}

interface Finding {
  id: string;
  scanId: string;
  ruleId: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  affectedObjects: Record<string, any>[];
  riskScore: number;
  status: 'active' | 'resolved' | 'ignored';
  createdAt: string;
}

class ApiClient {
  private baseURL: string;

  constructor(baseURL: string = API_BASE_URL) {
    this.baseURL = baseURL;
  }

  /**
   * Get JWT token from Supabase session
   */
  private async getAuthToken(): Promise<string | null> {
    const supabase = createClient();
    const { data: { session } } = await supabase.auth.getSession();
    
    // Debug logging
    if (session?.access_token) {
      console.log('🔑 JWT Token found, length:', session.access_token.length);
      console.log('🔑 Token prefix:', session.access_token.substring(0, 50) + '...');
    } else {
      console.warn('⚠️ No JWT token found in session');
    }
    
    return session?.access_token || null;
  }

  /**
   * Make authenticated API request
   */
  private async request<T>(
    endpoint: string, 
    options: RequestInit = {}
  ): Promise<T> {
    const token = await this.getAuthToken();
    
    if (!token) {
      throw new Error('Authentication required');
    }

    const url = `${this.baseURL}${endpoint}`;
    const config: RequestInit = {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
        ...options.headers,
      },
    };

    try {
      console.log('📡 Making API request to:', endpoint);
      console.log('🔗 Full URL:', url);
      const response = await fetch(url, config);

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        console.error('❌ API request failed:', response.status, errorData);
        throw new Error(
          errorData.message || 
          errorData.error || 
          `HTTP ${response.status}: ${response.statusText}`
        );
      }

      // Handle empty responses (e.g., 204 No Content)
      if (response.status === 204) {
        return {} as T;
      }

      return await response.json();
    } catch (error) {
      console.error(`API Request failed for ${endpoint}:`, error);
      throw error;
    }
  }

  // Dashboard API
  async getDashboardSummary(): Promise<DashboardSummary> {
    return this.request<DashboardSummary>('/analytics/dashboard');
  }

  // Scans API
  async getScans(params?: {
    page?: number;
    limit?: number;
    scanType?: string;
    status?: string;
    startDate?: string;
    endDate?: string;
  }): Promise<PaginatedResponse<Scan>> {
    const searchParams = new URLSearchParams();
    
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          // Ensure numbers are properly formatted
          if (typeof value === 'number') {
            searchParams.append(key, value.toString());
          } else {
            searchParams.append(key, String(value));
          }
        }
      });
    }

    const queryString = searchParams.toString();
    const endpoint = `/scans${queryString ? `?${queryString}` : ''}`;
    
    return this.request<PaginatedResponse<Scan>>(endpoint);
  }

  async getScan(scanId: string): Promise<Scan> {
    return this.request<Scan>(`/scans/${scanId}`);
  }

  async getScanResults(scanId: string): Promise<any> {
    return this.request(`/scans/${scanId}/results`);
  }

  // Findings API  
  async getFindings(params?: {
    page?: number;
    limit?: number;
    scanId?: string;
    severity?: string;
    status?: string;
  }): Promise<PaginatedResponse<Finding>> {
    const searchParams = new URLSearchParams();
    
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          searchParams.append(key, String(value));
        }
      });
    }

    const queryString = searchParams.toString();
    const endpoint = `/findings${queryString ? `?${queryString}` : ''}`;
    
    return this.request<PaginatedResponse<Finding>>(endpoint);
  }

  // Organizations API
  async getOrganization(): Promise<any> {
    return this.request('/organizations');
  }

  // Security Trends API
  async getSecurityTrends(days: number = 30): Promise<any> {
    return this.request(`/analytics/trends?days=${days}`);
  }

  // Compliance API
  async getComplianceScore(): Promise<any> {
    return this.request('/analytics/compliance');
  }
}

// Export singleton instance
export const apiClient = new ApiClient();

// Export types
export type {
  DashboardSummary,
  Scan,
  Finding,
  PaginatedResponse,
  ApiResponse,
};