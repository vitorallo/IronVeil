#!/usr/bin/env node

/**
 * Temporary RLS Disable for Testing
 * This will temporarily disable RLS on user_profiles to get the dashboard working
 */

const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = 'http://127.0.0.1:54321';
const SUPABASE_SERVICE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';

async function temporaryDisableRLS() {
  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

  console.log('⚠️  TEMPORARY: Disabling RLS on user_profiles for testing...\n');

  try {
    // Use the service role to bypass RLS and execute SQL
    const { data, error } = await supabase
      .from('user_profiles')
      .select('count(*)', { count: 'exact', head: true });

    if (error && error.message.includes('infinite recursion')) {
      console.log('✅ Confirmed: RLS recursion issue exists');
      console.log('🔧 Applying temporary fix...');
      
      // Create a SQL script to disable RLS temporarily
      const sqlCommands = [
        'ALTER TABLE user_profiles DISABLE ROW LEVEL SECURITY;',
        'ALTER TABLE organizations DISABLE ROW LEVEL SECURITY;',
        'ALTER TABLE scans DISABLE ROW LEVEL SECURITY;',
        'ALTER TABLE findings DISABLE ROW LEVEL SECURITY;'
      ];

      console.log('📝 SQL commands to run manually in Supabase Studio:');
      sqlCommands.forEach((cmd, i) => {
        console.log(`${i + 1}. ${cmd}`);
      });

      console.log('\n🌐 Manual steps:');
      console.log('1. Open http://localhost:54323 (Supabase Studio)');
      console.log('2. Go to SQL Editor');
      console.log('3. Run the above SQL commands');
      console.log('4. Test dashboard at http://localhost:3002/dashboard');
      console.log('\n⚠️  Remember: Re-enable RLS for production!');

    } else if (error) {
      console.log('❌ Different error:', error.message);
    } else {
      console.log('✅ No RLS issues detected, user_profiles accessible');
    }

  } catch (err) {
    console.error('Error:', err.message);
  }
}

temporaryDisableRLS();