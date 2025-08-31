#!/usr/bin/env node

/**
 * Simple IronVeil Database Seeder
 * Creates basic data for dashboard testing
 */

const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = 'http://127.0.0.1:54321';
const SUPABASE_SERVICE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';

const TEST_USER = {
  id: '30b8c881-f323-4d31-a232-a52e83a96782',
  email: 'test2@ironveil.local',
  organizationId: '550e8400-e29b-41d4-a716-446655440000'
};

async function seedDatabase() {
  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false }
  });

  console.log('🚀 Starting simple database seeding...\n');

  try {
    // 1. Create organization
    console.log('🏢 Creating organization...');
    const { data: orgData, error: orgError } = await supabase
      .from('organizations')
      .upsert([{
        id: TEST_USER.organizationId,
        name: 'Contoso Finance Corp',
        slug: 'contoso-finance',
        tier: 'enterprise',
        settings: { scanRetentionDays: 90 },
        subscription_data: { status: 'active' }
      }])
      .select();

    if (orgError) throw orgError;
    console.log('✅ Organization created');

    // 2. Create user profile
    console.log('👤 Creating user profile...');
    const { data: userData, error: userError } = await supabase
      .from('user_profiles')
      .upsert([{
        id: TEST_USER.id,
        organization_id: TEST_USER.organizationId,
        email: TEST_USER.email,
        full_name: 'John Security',
        role: 'admin',
        permissions: ['read', 'write', 'admin']
      }])
      .select();

    if (userError) throw userError;
    console.log('✅ User profile created');

    // 3. Create completed scans
    console.log('🔍 Creating scan results...');
    const scanIds = [
      '550e8401-e29b-41d4-a716-446655440001',
      '550e8402-e29b-41d4-a716-446655440002'
    ];

    const scansData = [
      {
        id: scanIds[0],
        organization_id: TEST_USER.organizationId,
        user_id: TEST_USER.id,
        name: 'Production Finance Domain Scan',
        description: 'Security assessment of production finance environment',
        scan_type: 'hybrid',
        status: 'completed',
        raw_data: { metadata: { domain: 'finance.contoso.com' } },
        overall_score: 75,
        risk_level: 'high',
        findings_summary: { total: 4, critical: 1, high: 2, medium: 1, low: 0 },
        started_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        completed_at: new Date(Date.now() - 24 * 60 * 60 * 1000 + 120000).toISOString(),
        created_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
      },
      {
        id: scanIds[1],
        organization_id: TEST_USER.organizationId,
        user_id: TEST_USER.id,
        name: 'HR Department Entra ID Review',
        description: 'Cloud identity security assessment',
        scan_type: 'entra_only',
        status: 'completed',
        raw_data: { metadata: { domain: 'hr.contoso.com' } },
        overall_score: 90,
        risk_level: 'medium',
        findings_summary: { total: 2, critical: 0, high: 1, medium: 1, low: 0 },
        started_at: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString(),
        completed_at: new Date(Date.now() - 12 * 60 * 60 * 1000 + 90000).toISOString(),
        created_at: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString()
      }
    ];

    const { data: scanResults, error: scanError } = await supabase
      .from('scans')
      .upsert(scansData)
      .select();

    if (scanError) throw scanError;
    console.log('✅ Scans created');

    // 4. Create findings
    console.log('🚨 Creating security findings...');
    const findingsData = [
      {
        id: '550e8501-e29b-41d4-a716-446655440501',
        scan_id: scanIds[0],
        organization_id: TEST_USER.organizationId,
        rule_id: 'AD-T1-006',
        rule_name: 'Unconstrained Delegation Detection',
        category: 'delegation',
        severity: 'critical',
        title: 'Unconstrained delegation on domain controllers',
        description: 'Domain controllers have unconstrained delegation enabled, allowing impersonation of any user.',
        affected_objects: ['DC01.finance.contoso.com', 'DC02.finance.contoso.com'],
        remediation: 'Remove unconstrained delegation and implement constrained delegation',
        risk_score: 100,
        impact_score: 10,
        likelihood_score: 10,
        status: 'open',
        created_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
      },
      {
        id: '550e8502-e29b-41d4-a716-446655440502',
        scan_id: scanIds[0],
        organization_id: TEST_USER.organizationId,
        rule_id: 'AD-T3-003',
        rule_name: 'Stale Privileged Accounts',
        category: 'accounts',
        severity: 'high',
        title: 'Inactive privileged accounts detected',
        description: 'Multiple privileged accounts have not been used recently but retain administrative access.',
        affected_objects: ['AdminJohnDoe', 'ServiceAccountSQL', 'BackupAdmin'],
        remediation: 'Disable unused privileged accounts and review permissions',
        risk_score: 85,
        impact_score: 9,
        likelihood_score: 9,
        status: 'in_progress',
        assignee_id: TEST_USER.id,
        created_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
      },
      {
        id: '550e8503-e29b-41d4-a716-446655440503',
        scan_id: scanIds[1],
        organization_id: TEST_USER.organizationId,
        rule_id: 'ENT-AUTH-001',
        rule_name: 'MFA Enforcement Check',
        category: 'authentication',
        severity: 'high',
        title: 'MFA not enforced for privileged users',
        description: 'Several privileged accounts do not have multi-factor authentication enabled.',
        affected_objects: ['admin@hr.contoso.com', 'hr-manager@contoso.com'],
        remediation: 'Enable MFA requirement for all privileged accounts',
        risk_score: 80,
        impact_score: 8,
        likelihood_score: 9,
        status: 'resolved',
        resolved_at: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(),
        resolution_notes: 'MFA policies implemented for all admin accounts',
        created_at: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString()
      }
    ];

    const { data: findingsResults, error: findingsError } = await supabase
      .from('findings')
      .upsert(findingsData)
      .select();

    if (findingsError) throw findingsError;
    console.log('✅ Findings created');

    // 5. Create API key
    console.log('🔑 Creating API key...');
    const { data: apiKeyData, error: apiKeyError } = await supabase
      .from('api_keys')
      .upsert([{
        id: '550e8410-e29b-41d4-a716-446655440010',
        organization_id: TEST_USER.organizationId,
        user_id: TEST_USER.id,
        name: 'Desktop Scanner - Finance Department',
        key_hash: '$2b$10$8K8hjQWgJrwq2VhwV3m5k.PD3gJpH7xSxLmdNBQKlrYl2XzrJbGmu',
        key_prefix: 'iv_test_api',
        permissions: ['scan:upload', 'scan:status'],
        is_active: true,
        expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
        created_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()
      }])
      .select();

    if (apiKeyError) throw apiKeyError;
    console.log('✅ API key created');

    console.log('\n🎉 Database seeding completed successfully!');
    console.log('\n📊 Summary:');
    console.log('   - Organizations: 1 (Contoso Finance Corp)');
    console.log('   - User Profiles: 1 (John Security)');
    console.log('   - Scans: 2 completed scans');
    console.log('   - Findings: 3 security findings (1 critical, 2 high)');
    console.log('   - API Keys: 1 active key');
    console.log('\n🌐 Ready to view:');
    console.log('   - Dashboard: http://localhost:3002/dashboard');
    console.log('   - Login: test2@ironveil.local / nokia347');

  } catch (error) {
    console.error('\n❌ Seeding failed:', error.message);
    console.error('Details:', error);
    process.exit(1);
  }
}

seedDatabase();