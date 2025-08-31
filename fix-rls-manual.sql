-- TEMPORARY FIX: Disable RLS for testing
-- Run this in Supabase Studio SQL Editor to fix infinite recursion

-- Disable RLS on problematic tables temporarily
ALTER TABLE user_profiles DISABLE ROW LEVEL SECURITY;
ALTER TABLE organizations DISABLE ROW LEVEL SECURITY;  
ALTER TABLE scans DISABLE ROW LEVEL SECURITY;
ALTER TABLE findings DISABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys DISABLE ROW LEVEL SECURITY;

-- Verify tables work now
SELECT 'user_profiles' as table_name, count(*) as count FROM user_profiles
UNION ALL
SELECT 'organizations' as table_name, count(*) as count FROM organizations  
UNION ALL
SELECT 'scans' as table_name, count(*) as count FROM scans
UNION ALL
SELECT 'findings' as table_name, count(*) as count FROM findings;

-- Note: This is a temporary fix for development
-- For production, proper RLS policies should be implemented