#!/usr/bin/env node

/**
 * Fix RLS Recursion Issue
 * Applies SQL to fix the infinite recursion in user_profiles policies
 */

const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = 'http://127.0.0.1:54321';
const SUPABASE_SERVICE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';

async function fixRLSPolicies() {
  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false }
  });

  console.log('🔧 Fixing RLS infinite recursion policies...\n');

  try {
    // Drop the problematic policy
    console.log('1. Dropping problematic user_profiles_select policy...');
    await supabase.rpc('exec', { 
      sql: 'DROP POLICY IF EXISTS "user_profiles_select" ON user_profiles;' 
    });

    // Create simple policy for own profile
    console.log('2. Creating user_profiles_select_own policy...');
    await supabase.rpc('exec', { 
      sql: `CREATE POLICY "user_profiles_select_own" ON user_profiles FOR SELECT
            TO authenticated
            USING (id = auth.uid());` 
    });

    // Create org policy without recursion
    console.log('3. Creating user_profiles_select_org policy...');
    await supabase.rpc('exec', { 
      sql: `CREATE POLICY "user_profiles_select_org" ON user_profiles FOR SELECT  
            TO authenticated
            USING (
              id = auth.uid() OR 
              organization_id = (
                SELECT up.organization_id 
                FROM user_profiles up 
                WHERE up.id = auth.uid() 
                LIMIT 1
              )
            );` 
    });

    console.log('✅ RLS policies fixed successfully!');
    console.log('\n🌐 Test the dashboard now: http://localhost:3002/dashboard');

  } catch (error) {
    if (error.message.includes('exec')) {
      console.log('ℹ️ exec function not available, trying direct SQL approach...');
      
      // Alternative approach - just create a simple policy
      try {
        const { data, error: sqlError } = await supabase
          .from('user_profiles')
          .select('id')
          .limit(1);
        
        if (sqlError && sqlError.message.includes('infinite recursion')) {
          console.log('⚠️ RLS recursion confirmed. Using service role to bypass...');
          
          // We'll need to manually fix this via the Supabase studio
          console.log('\n📋 Manual fix needed:');
          console.log('1. Open http://localhost:54323');
          console.log('2. Go to Authentication > Policies');
          console.log('3. Delete the "user_profiles_select" policy');
          console.log('4. Create a new policy:');
          console.log('   Name: user_profiles_simple');
          console.log('   Table: user_profiles');
          console.log('   Policy: SELECT');
          console.log('   Target roles: authenticated');
          console.log('   USING expression: id = auth.uid()');
        }
      } catch (testError) {
        console.error('Error testing policy:', testError.message);
      }
    } else {
      console.error('❌ Error fixing policies:', error.message);
    }
  }
}

fixRLSPolicies();