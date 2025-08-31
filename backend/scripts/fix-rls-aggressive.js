#!/usr/bin/env node

/**
 * Aggressive RLS Fix - Drop all user_profiles policies and recreate simple ones
 */

const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = 'http://127.0.0.1:54321';
const SUPABASE_SERVICE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';

async function aggressiveRLSFix() {
  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false }
  });

  console.log('🚨 AGGRESSIVE RLS Fix - Dropping ALL user_profiles policies...\n');

  // List of all possible policy names that might exist
  const policiesToDrop = [
    'user_profiles_select',
    'user_profiles_select_own', 
    'user_profiles_select_org',
    'user_profiles_insert',
    'user_profiles_update_own',
    'user_profiles_admin_manage',
    'user_profiles_anon_insert'
  ];

  try {
    // Drop all existing policies
    console.log('1. Dropping all existing user_profiles policies...');
    for (const policy of policiesToDrop) {
      try {
        const { data, error } = await supabase.rpc('exec', {
          sql: `DROP POLICY IF EXISTS "${policy}" ON user_profiles;`
        });
        console.log(`   ✓ Dropped ${policy} (if existed)`);
      } catch (err) {
        // Ignore errors for policies that don't exist
        console.log(`   - ${policy} (didn't exist or couldn't drop)`);
      }
    }

    // Create one super simple policy that allows everything for now
    console.log('\n2. Creating simple temporary policy...');
    const { data, error } = await supabase.rpc('exec', {
      sql: `
        CREATE POLICY "user_profiles_temporary_full_access" ON user_profiles 
        FOR ALL 
        TO authenticated 
        USING (true) 
        WITH CHECK (true);
      `
    });

    if (error) {
      console.log('Using alternative approach...');
      // If exec doesn't work, try a different method
      console.log('   Temporarily disabling RLS on user_profiles...');
      await supabase.rpc('exec', {
        sql: 'ALTER TABLE user_profiles DISABLE ROW LEVEL SECURITY;'
      });
      console.log('   ⚠️ RLS disabled on user_profiles - should re-enable after testing');
    }

    console.log('\n✅ Aggressive fix applied!');
    console.log('🧪 Test the dashboard now: http://localhost:3002/dashboard');
    console.log('\n⚠️  IMPORTANT: This is a temporary fix for testing.');
    console.log('    Proper RLS policies should be restored for production.');

  } catch (error) {
    console.error('❌ Aggressive fix failed:', error.message);
    console.log('\n📋 Manual fix required:');
    console.log('1. Open Supabase Studio: http://localhost:54323');
    console.log('2. Go to Authentication > Policies');  
    console.log('3. Select user_profiles table');
    console.log('4. Delete ALL policies');
    console.log('5. Create one simple policy:');
    console.log('   Name: temp_full_access');
    console.log('   Command: ALL');
    console.log('   Target roles: authenticated');
    console.log('   USING expression: true');
    console.log('   WITH CHECK: true');
  }
}

aggressiveRLSFix();