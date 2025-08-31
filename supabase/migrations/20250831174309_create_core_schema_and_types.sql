-- IronVeil MicroSaaS Database Schema
-- Phase 1.1: Core Schema & Authentication
-- Development Environment: Mac Primary

-- Create custom types for better data consistency
CREATE TYPE tier_enum AS ENUM ('community', 'enterprise', 'easm');
CREATE TYPE user_role_enum AS ENUM ('admin', 'user', 'viewer', 'api_only');
CREATE TYPE scan_type_enum AS ENUM ('ad_only', 'entra_only', 'hybrid', 'custom');
CREATE TYPE scan_status_enum AS ENUM ('pending', 'processing', 'completed', 'failed', 'cancelled');
CREATE TYPE risk_level_enum AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE severity_enum AS ENUM ('critical', 'high', 'medium', 'low');
CREATE TYPE finding_status_enum AS ENUM ('open', 'in_progress', 'resolved', 'false_positive', 'accepted_risk');

-- Organizations (Multi-tenant root)
CREATE TABLE organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  tier tier_enum NOT NULL DEFAULT 'community',
  settings JSONB DEFAULT '{}',
  subscription_data JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  
  CONSTRAINT valid_slug CHECK (slug ~ '^[a-z0-9-]+$' AND length(slug) >= 3)
);

-- Custom user profiles linked to Supabase Auth
CREATE TABLE user_profiles (
  id UUID REFERENCES auth.users ON DELETE CASCADE PRIMARY KEY,
  organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  full_name TEXT,
  role user_role_enum NOT NULL DEFAULT 'user',
  permissions TEXT[] DEFAULT '{}',
  last_login TIMESTAMPTZ,
  preferences JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  
  CONSTRAINT valid_email CHECK (email ~ '^[^@]+@[^@]+\.[^@]+$')
);

-- Scan results with full metadata
CREATE TABLE scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE NOT NULL,
  user_id UUID REFERENCES user_profiles(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  description TEXT,
  scan_type scan_type_enum NOT NULL,
  status scan_status_enum NOT NULL DEFAULT 'processing',
  
  -- Scan data and results
  raw_data JSONB NOT NULL,
  processed_results JSONB DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  
  -- Calculated scores and metrics
  overall_score INTEGER CHECK (overall_score >= 0 AND overall_score <= 100),
  risk_level risk_level_enum,
  findings_summary JSONB DEFAULT '{}',
  
  -- Timing and processing info
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  processing_duration INTERVAL,
  
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  
  CONSTRAINT valid_scan_name CHECK (length(name) >= 1 AND length(name) <= 255)
);

-- Individual findings from scans
CREATE TABLE findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE NOT NULL,
  organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE NOT NULL,
  
  -- Finding identification
  rule_id TEXT NOT NULL,
  rule_name TEXT NOT NULL,
  category TEXT NOT NULL,
  severity severity_enum NOT NULL,
  
  -- Finding details
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  affected_objects JSONB DEFAULT '[]',
  remediation TEXT,
  external_references JSONB DEFAULT '[]',
  
  -- Risk assessment
  risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
  impact_score INTEGER CHECK (impact_score >= 0 AND impact_score <= 10),
  likelihood_score INTEGER CHECK (likelihood_score >= 0 AND likelihood_score <= 10),
  
  -- Status tracking
  status finding_status_enum DEFAULT 'open',
  assignee_id UUID REFERENCES user_profiles(id) ON DELETE SET NULL,
  resolved_at TIMESTAMPTZ,
  resolution_notes TEXT,
  
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  
  CONSTRAINT valid_finding_title CHECK (length(title) >= 1 AND length(title) <= 500),
  CONSTRAINT valid_rule_id CHECK (length(rule_id) >= 1 AND length(rule_id) <= 100)
);

-- Historical trends and analytics
CREATE TABLE analytics_snapshots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE NOT NULL,
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  
  snapshot_date DATE NOT NULL,
  metrics JSONB NOT NULL, -- Store calculated metrics
  trends JSONB DEFAULT '{}', -- Trend calculations
  
  created_at TIMESTAMPTZ DEFAULT NOW(),
  
  UNIQUE(organization_id, snapshot_date)
);

-- API keys for desktop scanner authentication
CREATE TABLE api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE NOT NULL,
  user_id UUID REFERENCES user_profiles(id) ON DELETE CASCADE NOT NULL,
  
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE, -- Store hashed version
  key_prefix TEXT NOT NULL, -- Store first few chars for display
  permissions TEXT[] DEFAULT '{"scan:upload", "scan:read"}',
  
  last_used_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  is_active BOOLEAN DEFAULT true,
  
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  
  CONSTRAINT valid_key_name CHECK (length(name) >= 1 AND length(name) <= 100)
);

-- Create essential indexes for performance
CREATE INDEX idx_organizations_tier ON organizations(tier);
CREATE INDEX idx_organizations_slug ON organizations(slug);

CREATE INDEX idx_user_profiles_org ON user_profiles(organization_id);
CREATE INDEX idx_user_profiles_email ON user_profiles(email);
CREATE INDEX idx_user_profiles_role ON user_profiles(organization_id, role);

CREATE INDEX idx_scans_org_created ON scans(organization_id, created_at DESC);
CREATE INDEX idx_scans_status ON scans(status) WHERE status != 'completed';
CREATE INDEX idx_scans_user ON scans(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_scans_type ON scans(scan_type);

CREATE INDEX idx_findings_scan_severity ON findings(scan_id, severity);
CREATE INDEX idx_findings_org_status ON findings(organization_id, status);
CREATE INDEX idx_findings_category ON findings(organization_id, category);
CREATE INDEX idx_findings_rule ON findings(rule_id);

-- Composite indexes for analytics queries
CREATE INDEX idx_findings_analytics ON findings(organization_id, created_at, severity) 
  WHERE status = 'open';
CREATE INDEX idx_scans_analytics ON scans(organization_id, created_at, status) 
  WHERE status = 'completed';

CREATE INDEX idx_analytics_snapshots_org_date ON analytics_snapshots(organization_id, snapshot_date DESC);

CREATE INDEX idx_api_keys_org_active ON api_keys(organization_id, is_active) WHERE is_active = true;
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash) WHERE is_active = true;

-- Add helpful comments
COMMENT ON TABLE organizations IS 'Multi-tenant organizations with tier-based features';
COMMENT ON TABLE user_profiles IS 'Custom user profiles linked to Supabase auth with organization membership';
COMMENT ON TABLE scans IS 'Security scan results from desktop scanner applications';
COMMENT ON TABLE findings IS 'Individual security findings extracted from scans';
COMMENT ON TABLE analytics_snapshots IS 'Historical analytics data for trend analysis';
COMMENT ON TABLE api_keys IS 'API keys for desktop scanner authentication';

COMMENT ON COLUMN organizations.tier IS 'Subscription tier: community (basic), enterprise (advanced), easm (integration)';
COMMENT ON COLUMN scans.raw_data IS 'Original JSON data uploaded from desktop scanner';
COMMENT ON COLUMN scans.processed_results IS 'Processed and normalized scan results';
COMMENT ON COLUMN findings.affected_objects IS 'JSON array of affected AD/Entra ID objects';
COMMENT ON COLUMN api_keys.key_hash IS 'Hashed API key for secure storage';