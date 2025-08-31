#!/usr/bin/env node

/**
 * IronVeil Local Database Seed Script
 * 
 * Seeds the local Supabase database with sample data for development
 * and testing the dashboard UI with realistic content.
 */

const { createClient } = require('@supabase/supabase-js');

// Local Supabase configuration
const SUPABASE_URL = 'http://127.0.0.1:54321';
const SUPABASE_SERVICE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';

// Test user details (matches our test setup)
const TEST_USER = {
  id: '74a35b27-75ff-470e-b7e5-20badea43db5', // From JWT token we got
  email: 'test2@ironveil.local',
  organizationId: '550e8400-e29b-41d4-a716-446655440000' // Valid UUID format
};

class DatabaseSeeder {
  constructor() {
    this.supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    });
  }

  async seedOrganizations() {
    console.log('🏢 Seeding organizations...');
    
    const orgData = {
      id: TEST_USER.organizationId,
      name: 'Contoso Finance Corp',
      slug: 'contoso-finance-corp',
      tier: 'enterprise',
      settings: {
        scanRetentionDays: 90,
        maxScansPerMonth: 500,
        enableRealTimeUpdates: true,
        allowApiAccess: true,
        customBranding: true
      },
      subscription_data: {
        status: 'active',
        plan: 'enterprise-monthly',
        billing_cycle: 'monthly',
        expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
      },
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    const { data, error } = await this.supabase
      .from('organizations')
      .upsert([orgData])
      .select();

    if (error) {
      console.error('❌ Error seeding organizations:', error);
      return false;
    }

    console.log('✅ Organizations seeded:', data?.length || 0);
    return true;
  }

  async seedUserProfiles() {
    console.log('👤 Seeding user profiles...');
    
    const profileData = {
      id: TEST_USER.id,
      organization_id: TEST_USER.organizationId,
      email: TEST_USER.email,
      full_name: 'John Security',
      role: 'admin',
      permissions: ['read', 'write', 'admin'],
      preferences: {
        theme: 'dark',
        notifications: true,
        dashboardLayout: 'detailed'
      },
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    const { data, error } = await this.supabase
      .from('user_profiles')
      .upsert([profileData])
      .select();

    if (error) {
      console.error('❌ Error seeding user profiles:', error);
      return false;
    }

    console.log('✅ User profiles seeded:', data?.length || 0);
    return true;
  }

  async seedScans() {
    console.log('🔍 Seeding scan results...');
    
    const scansData = [
      {
        id: '550e8401-e29b-41d4-a716-446655440001',
        organization_id: TEST_USER.organizationId,
        user_id: TEST_USER.id,
        name: 'Production AD Security Scan - Finance Domain',
        description: 'Comprehensive security assessment of the finance domain environment',
        scan_type: 'hybrid',
        status: 'completed',
        raw_data: {
          metadata: {
            domain: 'finance.contoso.com',
            executionTime: 145.7,
            rulesetVersion: '2.1.0',
            scannerVersion: '1.2.1',
            scanId: 'scan-finance-prod-001',
            timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
            tenantId: TEST_USER.organizationId
          },
          findings: []
        },
        processed_results: {
          summary: {
            totalFindings: 4,
            criticalCount: 1,
            highCount: 2,
            mediumCount: 1,
            lowCount: 0,
            overallScore: 81.25,
            riskLevel: 'high'
          }
        },
        overall_score: 81,
        risk_level: 'high',
        findings_summary: {
          total: 4,
          critical: 1,
          high: 2,
          medium: 1,
          low: 0
        },
        started_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        completed_at: new Date(Date.now() - 24 * 60 * 60 * 1000 + 2 * 60 * 1000).toISOString(),
        processing_duration: '00:02:00',
        created_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
      },
      {
        id: '550e8402-e29b-41d4-a716-446655440002',
        organization_id: TEST_USER.organizationId,
        user_id: TEST_USER.id,
        name: 'HR Department Security Assessment',
        description: 'Entra ID security review for HR department',
        scan_type: 'entra_only',
        status: 'completed',
        raw_data: {
          metadata: {
            domain: 'hr.contoso.com',
            executionTime: 89.3,
            rulesetVersion: '2.1.0',
            scannerVersion: '1.2.1',
            scanId: 'scan-hr-test-002',
            timestamp: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString(),
            tenantId: TEST_USER.organizationId
          },
          findings: []
        },
        processed_results: {
          summary: {
            totalFindings: 2,
            criticalCount: 0,
            highCount: 1,
            mediumCount: 1,
            lowCount: 0,
            overallScore: 92.5,
            riskLevel: 'medium'
          }
        },
        overall_score: 92,
        risk_level: 'medium',
        findings_summary: {
          total: 2,
          critical: 0,
          high: 1,
          medium: 1,
          low: 0
        },
        started_at: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString(),
        completed_at: new Date(Date.now() - 12 * 60 * 60 * 1000 + 90 * 1000).toISOString(),
        processing_duration: '00:01:30',
        created_at: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString()
      },
      {
        id: '550e8403-e29b-41d4-a716-446655440003',
        organization_id: TEST_USER.organizationId,
        user_id: TEST_USER.id,
        name: 'Development Environment Quick Scan',
        description: 'Active Directory scan of development environment',
        scan_type: 'ad_only',
        status: 'processing',
        raw_data: {
          metadata: {
            domain: 'dev.contoso.com',
            executionTime: null,
            rulesetVersion: '2.1.0',
            scannerVersion: '1.2.1',
            scanId: 'scan-dev-env-003',
            timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
            tenantId: TEST_USER.organizationId
          },
          findings: []
        },
        processed_results: {},
        overall_score: null,
        risk_level: null,
        findings_summary: null,
        started_at: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
        completed_at: null,
        processing_duration: null,
        created_at: new Date(Date.now() - 5 * 60 * 1000).toISOString()
      }
    ];

    const { data, error } = await this.supabase
      .from('scans')
      .upsert(scansData)
      .select();

    if (error) {
      console.error('❌ Error seeding scans:', error);
      return false;
    }

    console.log('✅ Scans seeded:', data?.length || 0);
    return true;
  }

  async seedFindings() {
    console.log('🚨 Seeding security findings...');
    
    const findingsData = [
      // Critical findings from finance scan
      {
        id: '550e8501-e29b-41d4-a716-446655440501',
        scan_id: '550e8401-e29b-41d4-a716-446655440001',
        organization_id: TEST_USER.organizationId,
        rule_id: 'AD-T1-006',
        rule_name: 'Unconstrained Delegation Detection',
        category: 'delegation',
        severity: 'critical',
        title: 'Unconstrained delegation detected on domain controllers',
        description: 'Domain controllers have unconstrained delegation enabled, which allows them to impersonate any user account in the domain.',
        affected_objects: ['DC01.finance.contoso.com', 'DC02.finance.contoso.com'],
        remediation: 'Remove unconstrained delegation from computer accounts and implement constrained delegation',
        external_references: [
          { 'name': 'MITRE ATT&CK T1558.003', 'url': 'https://attack.mitre.org/techniques/T1558/003/' }
        ],
        risk_score: 100,
        impact_score: 10,
        likelihood_score: 10,
        status: 'open',
        assignee_id: null,
        resolved_at: null,
        resolution_notes: null,
        created_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        updated_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
      },
      {
        id: '550e8502-e29b-41d4-a716-446655440502',
        scan_id: '550e8401-e29b-41d4-a716-446655440001',
        organization_id: TEST_USER.organizationId,
        rule_id: 'AD-T3-003',
        rule_name: 'Stale Privileged Accounts Detection',
        category: 'accounts',
        severity: 'high',
        title: 'Stale privileged accounts with excessive permissions',
        description: 'Multiple privileged accounts have not been used recently but retain administrative access.',
        affected_objects: ['AdminJohnDoe', 'ServiceAccountSQL', 'BackupAdmin'],
        remediation: 'Disable unused privileged accounts and review service account permissions',
        external_references: [],
        risk_score: 85,
        impact_score: 9,
        likelihood_score: 9,
        status: 'in_progress',
        assignee_id: TEST_USER.id,
        resolved_at: null,
        resolution_notes: 'Assigned to security team for review',
        created_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
      },
      {
        id: '550e8503-e29b-41d4-a716-446655440503',
        scan_id: '550e8401-e29b-41d4-a716-446655440001',
        organization_id: TEST_USER.organizationId,
        rule_id: 'ENT-AUTH-001',
        rule_name: 'MFA Enforcement Check',
        category: 'authentication',
        severity: 'high',
        title: 'MFA not enforced for all privileged users',
        description: 'Several privileged user accounts do not have multi-factor authentication enabled.',
        affected_objects: ['admin@finance.contoso.com', 'dbadmin@finance.contoso.com'],
        remediation: 'Enable MFA requirement for all privileged accounts and conditional access policies',
        external_references: [],
        risk_score: 80,
        impact_score: 8,
        likelihood_score: 9,
        status: 'in_progress',
        assignee_id: null,
        resolved_at: null,
        resolution_notes: null,
        created_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
      },
      {
        id: 'finding-004',
        scan_id: 'scan-finance-prod-001',
        organization_id: TEST_USER.organizationId,
        rule_id: 'AD-GPO-005',
        severity: 'medium',
        category: 'configuration',
        title: 'Weak password policy in default domain policy',
        description: 'The default domain password policy does not meet current security standards.',
        affected_objects: ['Default Domain Policy'],
        risk_score: 60,
        impact_score: 55,
        remediation: 'Strengthen password complexity requirements and enable account lockout policies',
        status: 'resolved',
        created_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
      },
      // HR scan findings
      {
        id: 'finding-005',
        scan_id: 'scan-hr-test-002',
        organization_id: TEST_USER.organizationId,
        rule_id: 'ENT-PRIV-002',
        severity: 'high',
        category: 'privileges',
        title: 'Excessive global administrator assignments',
        description: 'Too many users have been assigned global administrator roles in Entra ID.',
        affected_objects: ['hr-admin@contoso.com', 'backup-admin@contoso.com'],
        risk_score: 75,
        impact_score: 82,
        remediation: 'Review and reduce global administrator assignments, use PIM where possible',
        status: 'open',
        created_at: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString()
      },
      {
        id: 'finding-006',
        scan_id: 'scan-hr-test-002',
        organization_id: TEST_USER.organizationId,
        rule_id: 'ENT-APP-001',
        severity: 'medium',
        category: 'applications',
        title: 'Unmanaged application registrations',
        description: 'Several application registrations exist without proper governance.',
        affected_objects: ['HR-Portal-App', 'Legacy-TimeTracking'],
        risk_score: 55,
        impact_score: 60,
        remediation: 'Review application registrations and implement app governance policies',
        status: 'open',
        created_at: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString()
      }
    ];

    const { data, error } = await this.supabase
      .from('findings')
      .upsert(findingsData)
      .select();

    if (error) {
      console.error('❌ Error seeding findings:', error);
      return false;
    }

    console.log('✅ Findings seeded:', data?.length || 0);
    return true;
  }

  async seedApiKeys() {
    console.log('🔑 Seeding API keys...');
    
    const apiKeyData = {
      id: '550e8410-e29b-41d4-a716-446655440010',
      organization_id: TEST_USER.organizationId,
      user_id: TEST_USER.id,
      name: 'Desktop Scanner - Finance Department',
      key_hash: '$2b$10$8K8hjQWgJrwq2VhwV3m5k.PD3gJpH7xSxLmdNBQKlrYl2XzrJbGmu', // Hash of 'iv_test_api_key_for_desktop_scanner_12345678'
      key_prefix: 'iv_test_api',
      permissions: ['scan:upload', 'scan:status'],
      is_active: true,
      last_used_at: new Date(Date.now() - 60 * 60 * 1000).toISOString(), // 1 hour ago
      expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year from now
      created_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days ago
      updated_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()
    };

    const { data, error } = await this.supabase
      .from('api_keys')
      .upsert([apiKeyData])
      .select();

    if (error) {
      console.error('❌ Error seeding API keys:', error);
      return false;
    }

    console.log('✅ API keys seeded:', data?.length || 0);
    return true;
  }

  async run() {
    console.log('🚀 Starting IronVeil Local Database Seeding');
    console.log(`📡 Target: ${SUPABASE_URL}`);
    console.log(`👤 Test User: ${TEST_USER.email} (${TEST_USER.id})`);
    console.log('');

    try {
      // Seed data in proper order due to foreign key dependencies
      const results = await Promise.all([
        this.seedOrganizations(),
        // Wait for organizations before user profiles
      ]);

      if (!results[0]) {
        throw new Error('Failed to seed organizations');
      }

      const userResult = await this.seedUserProfiles();
      if (!userResult) {
        throw new Error('Failed to seed user profiles');
      }

      // Now seed dependent data
      const dependentResults = await Promise.all([
        this.seedScans(),
        this.seedApiKeys(),
      ]);

      if (!dependentResults.every(r => r)) {
        throw new Error('Failed to seed scans or API keys');
      }

      // Finally seed findings (depends on scans)
      const findingsResult = await this.seedFindings();
      if (!findingsResult) {
        throw new Error('Failed to seed findings');
      }

      console.log('');
      console.log('🎉 Database seeding completed successfully!');
      console.log('');
      console.log('📊 Summary:');
      console.log('   - Organizations: 1 (Contoso Finance Corp)');
      console.log('   - User Profiles: 1 (John Security)');
      console.log('   - Scans: 3 (2 completed, 1 processing)');
      console.log('   - Findings: 6 (4 from finance, 2 from HR)');
      console.log('   - API Keys: 1 (Desktop Scanner)');
      console.log('');
      console.log('🌐 Ready to test:');
      console.log('   - Frontend Dashboard: http://localhost:3002/dashboard');
      console.log('   - Backend API: http://localhost:3001/api');
      console.log('   - User Login: test2@ironveil.local / nokia347');

    } catch (error) {
      console.error('');
      console.error('❌ Database seeding failed:', error.message);
      process.exit(1);
    }
  }
}

// Run the seeder if called directly
if (require.main === module) {
  const seeder = new DatabaseSeeder();
  seeder.run().catch(console.error);
}

module.exports = DatabaseSeeder;