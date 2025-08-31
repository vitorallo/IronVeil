-- IronVeil MicroSaaS Row Level Security Policies
-- Phase 1.1: Multi-tenant Data Isolation & Authentication
-- Development Environment: Mac Primary

-- Enable Row Level Security on all tables
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE analytics_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

-- Organizations: Users can only access their own organization
CREATE POLICY "org_isolation" ON organizations FOR ALL 
TO authenticated
USING (
  id = (
    SELECT up.organization_id 
    FROM user_profiles up 
    WHERE up.id = auth.uid() 
    LIMIT 1
  )
);

-- User profiles: Users can see their own profile and profiles in their organization
CREATE POLICY "user_profiles_select" ON user_profiles FOR SELECT
TO authenticated
USING (
  id = auth.uid() OR
  organization_id = (
    SELECT up.organization_id 
    FROM user_profiles up 
    WHERE up.id = auth.uid() 
    LIMIT 1
  )
);

-- Users can insert their own profile during registration
CREATE POLICY "user_profiles_insert" ON user_profiles FOR INSERT
TO authenticated
WITH CHECK (id = auth.uid());

-- Users can update their own profile
CREATE POLICY "user_profiles_update_own" ON user_profiles FOR UPDATE
TO authenticated
USING (id = auth.uid())
WITH CHECK (id = auth.uid());

-- Admins can manage user profiles in their organization
CREATE POLICY "user_profiles_admin_manage" ON user_profiles FOR ALL
TO authenticated
USING (
  EXISTS (
    SELECT 1 FROM user_profiles up
    WHERE up.id = auth.uid() 
      AND up.role = 'admin'
      AND up.organization_id = user_profiles.organization_id
  )
);

-- Scans: Users can only access scans from their organization
CREATE POLICY "scans_org_policy" ON scans FOR ALL
TO authenticated
USING (
  organization_id = (
    SELECT up.organization_id 
    FROM user_profiles up 
    WHERE up.id = auth.uid() 
    LIMIT 1
  )
);

-- Findings: Users can only access findings from their organization scans
CREATE POLICY "findings_org_policy" ON findings FOR ALL
TO authenticated
USING (
  organization_id = (
    SELECT up.organization_id 
    FROM user_profiles up 
    WHERE up.id = auth.uid() 
    LIMIT 1
  )
);

-- Analytics snapshots: Organization isolation
CREATE POLICY "analytics_org_policy" ON analytics_snapshots FOR ALL
TO authenticated
USING (
  organization_id IN (
    SELECT organization_id FROM user_profiles WHERE id = auth.uid()
  )
);

-- API keys: Users can view API keys in their organization
CREATE POLICY "api_keys_view" ON api_keys FOR SELECT
TO authenticated
USING (
  organization_id IN (
    SELECT organization_id FROM user_profiles WHERE id = auth.uid()
  )
);

-- Only admins can create/delete API keys
CREATE POLICY "api_keys_admin_manage" ON api_keys FOR INSERT
TO authenticated
WITH CHECK (
  organization_id IN (
    SELECT organization_id FROM user_profiles 
    WHERE id = auth.uid() AND role IN ('admin')
  )
);

CREATE POLICY "api_keys_admin_delete" ON api_keys FOR DELETE
TO authenticated
USING (
  organization_id IN (
    SELECT organization_id FROM user_profiles 
    WHERE id = auth.uid() AND role IN ('admin')
  )
);

-- API keys can be updated by admins or the user who created them
CREATE POLICY "api_keys_update" ON api_keys FOR UPDATE
TO authenticated
USING (
  organization_id IN (
    SELECT organization_id FROM user_profiles WHERE id = auth.uid()
  ) AND (
    user_id = auth.uid() OR 
    EXISTS (
      SELECT 1 FROM user_profiles 
      WHERE id = auth.uid() AND role IN ('admin')
    )
  )
);

-- Create security definer functions to optimize RLS performance
CREATE OR REPLACE FUNCTION public.get_user_organization_id()
RETURNS UUID
LANGUAGE SQL
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
  SELECT organization_id
  FROM user_profiles
  WHERE id = auth.uid()
$$;

CREATE OR REPLACE FUNCTION public.get_user_role()
RETURNS user_role_enum
LANGUAGE SQL
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
  SELECT role
  FROM user_profiles
  WHERE id = auth.uid()
$$;

-- Optimized policies using security definer functions
-- (We'll keep the existing policies for now, but these can be used for better performance)

-- Grant necessary permissions to authenticated users
GRANT USAGE ON SCHEMA public TO authenticated;
GRANT ALL ON ALL TABLES IN SCHEMA public TO authenticated;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO authenticated;

-- Anonymous users can only read organizations for public signup pages
CREATE POLICY "organizations_public_read" ON organizations FOR SELECT
TO anon
USING (true);

-- Allow anonymous access for registration
CREATE POLICY "user_profiles_anon_insert" ON user_profiles FOR INSERT
TO anon
WITH CHECK (true);

-- Special policy for service role (used by API)
CREATE POLICY "service_role_full_access" ON organizations FOR ALL
TO service_role
USING (true)
WITH CHECK (true);

CREATE POLICY "service_role_profiles_full_access" ON user_profiles FOR ALL
TO service_role
USING (true)
WITH CHECK (true);

CREATE POLICY "service_role_scans_full_access" ON scans FOR ALL
TO service_role
USING (true)
WITH CHECK (true);

CREATE POLICY "service_role_findings_full_access" ON findings FOR ALL
TO service_role
USING (true)
WITH CHECK (true);

CREATE POLICY "service_role_analytics_full_access" ON analytics_snapshots FOR ALL
TO service_role
USING (true)
WITH CHECK (true);

CREATE POLICY "service_role_api_keys_full_access" ON api_keys FOR ALL
TO service_role
USING (true)
WITH CHECK (true);

-- Add helpful comments
COMMENT ON POLICY "org_isolation" ON organizations IS 'Users can only access their own organization data';
COMMENT ON POLICY "scans_org_policy" ON scans IS 'Multi-tenant isolation for scan data';
COMMENT ON POLICY "findings_org_policy" ON findings IS 'Security findings isolated by organization';

COMMENT ON FUNCTION public.get_user_organization_id() IS 'Security definer function to get current user organization ID for RLS optimization';
COMMENT ON FUNCTION public.get_user_role() IS 'Security definer function to get current user role for RLS optimization';