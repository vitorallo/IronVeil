-- IronVeil MicroSaaS Analytics & Scoring Functions
-- Phase 1.1: Database Functions for Analytics and Scoring
-- Development Environment: Mac Primary

-- Calculate organization security score based on recent scans
CREATE OR REPLACE FUNCTION calculate_org_security_score(org_id UUID, days_back INTEGER DEFAULT 30)
RETURNS INTEGER AS $$
DECLARE
  avg_score INTEGER;
BEGIN
  SELECT COALESCE(AVG(overall_score), 0)::INTEGER
  INTO avg_score
  FROM scans
  WHERE organization_id = org_id 
    AND status = 'completed'
    AND created_at > NOW() - (days_back || ' days')::INTERVAL;
    
  RETURN avg_score;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Get findings trend data for dashboard
CREATE OR REPLACE FUNCTION get_findings_trend(org_id UUID, days_back INTEGER DEFAULT 30)
RETURNS TABLE(
  date DATE, 
  critical_count BIGINT, 
  high_count BIGINT, 
  medium_count BIGINT, 
  low_count BIGINT
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    DATE(f.created_at) as date,
    COUNT(*) FILTER (WHERE f.severity = 'critical') as critical_count,
    COUNT(*) FILTER (WHERE f.severity = 'high') as high_count,
    COUNT(*) FILTER (WHERE f.severity = 'medium') as medium_count,
    COUNT(*) FILTER (WHERE f.severity = 'low') as low_count
  FROM findings f
  JOIN scans s ON f.scan_id = s.id
  WHERE s.organization_id = org_id
    AND f.created_at > NOW() - (days_back || ' days')::INTERVAL
    AND s.status = 'completed'
  GROUP BY DATE(f.created_at)
  ORDER BY date DESC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Calculate risk score for individual findings
CREATE OR REPLACE FUNCTION calculate_finding_risk_score(
  severity_level severity_enum,
  impact_score INTEGER DEFAULT NULL,
  likelihood_score INTEGER DEFAULT NULL,
  affected_object_count INTEGER DEFAULT 1
) RETURNS INTEGER AS $$
DECLARE
  base_score INTEGER;
  final_score INTEGER;
  impact_multiplier DECIMAL := 1.0;
  likelihood_multiplier DECIMAL := 1.0;
  volume_multiplier DECIMAL := 1.0;
BEGIN
  -- Base scores by severity
  CASE severity_level
    WHEN 'critical' THEN base_score := 90;
    WHEN 'high' THEN base_score := 70;
    WHEN 'medium' THEN base_score := 50;
    WHEN 'low' THEN base_score := 20;
    ELSE base_score := 10;
  END CASE;

  -- Apply impact multiplier if provided
  IF impact_score IS NOT NULL THEN
    impact_multiplier := (impact_score / 10.0) * 1.5;
  END IF;

  -- Apply likelihood multiplier if provided  
  IF likelihood_score IS NOT NULL THEN
    likelihood_multiplier := (likelihood_score / 10.0) * 1.3;
  END IF;

  -- Apply volume multiplier (more affected objects = higher risk)
  IF affected_object_count > 1 THEN
    volume_multiplier := LEAST(1.0 + (affected_object_count * 0.1), 2.0);
  END IF;

  -- Calculate final score
  final_score := (base_score * impact_multiplier * likelihood_multiplier * volume_multiplier)::INTEGER;
  
  -- Ensure score stays within bounds
  RETURN LEAST(100, GREATEST(0, final_score));
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Get organization dashboard summary
CREATE OR REPLACE FUNCTION get_organization_dashboard_summary(org_id UUID)
RETURNS JSON AS $$
DECLARE
  result JSON;
BEGIN
  SELECT json_build_object(
    'organization_id', org_id,
    'total_scans', COUNT(DISTINCT s.id),
    'recent_scans', COUNT(DISTINCT s.id) FILTER (WHERE s.created_at > NOW() - INTERVAL '30 days'),
    'average_security_score', COALESCE(AVG(s.overall_score), 0)::INTEGER,
    'total_findings', COUNT(f.id),
    'critical_findings', COUNT(f.id) FILTER (WHERE f.severity = 'critical' AND f.status = 'open'),
    'high_findings', COUNT(f.id) FILTER (WHERE f.severity = 'high' AND f.status = 'open'),
    'medium_findings', COUNT(f.id) FILTER (WHERE f.severity = 'medium' AND f.status = 'open'),
    'low_findings', COUNT(f.id) FILTER (WHERE f.severity = 'low' AND f.status = 'open'),
    'resolved_findings', COUNT(f.id) FILTER (WHERE f.status = 'resolved'),
    'last_scan_date', MAX(s.created_at),
    'scan_types', json_object_agg(s.scan_type, COUNT(s.id)) FILTER (WHERE s.scan_type IS NOT NULL)
  )
  INTO result
  FROM scans s
  LEFT JOIN findings f ON s.id = f.scan_id
  WHERE s.organization_id = org_id
    AND s.status = 'completed';
    
  RETURN result;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Process incoming scan data from desktop application
CREATE OR REPLACE FUNCTION process_desktop_scan(
  p_org_id UUID,
  p_user_id UUID,
  p_scan_name TEXT,
  p_scan_type scan_type_enum,
  p_scan_data JSONB
) RETURNS UUID AS $$
DECLARE
  scan_id UUID;
  finding_data JSONB;
  finding_record RECORD;
  calculated_risk_score INTEGER;
  affected_count INTEGER;
BEGIN
  -- Validate input
  IF p_scan_data IS NULL OR p_scan_data = '{}'::JSONB THEN
    RAISE EXCEPTION 'Scan data cannot be empty';
  END IF;

  -- Insert scan record
  INSERT INTO scans (
    organization_id, 
    user_id, 
    name, 
    scan_type, 
    raw_data, 
    status,
    started_at,
    overall_score,
    metadata
  )
  VALUES (
    p_org_id, 
    p_user_id, 
    p_scan_name, 
    p_scan_type, 
    p_scan_data, 
    'processing',
    NOW(),
    COALESCE((p_scan_data->>'overallScore')::INTEGER, 0),
    COALESCE(p_scan_data->'metadata', '{}'::JSONB)
  )
  RETURNING id INTO scan_id;

  -- Process findings if they exist in scan data
  IF p_scan_data ? 'findings' THEN
    FOR finding_data IN SELECT * FROM jsonb_array_elements(p_scan_data->'findings')
    LOOP
      -- Count affected objects
      affected_count := COALESCE(jsonb_array_length(finding_data->'affectedObjects'), 1);
      
      -- Calculate risk score
      calculated_risk_score := calculate_finding_risk_score(
        (finding_data->>'severity')::severity_enum,
        (finding_data->>'impactScore')::INTEGER,
        (finding_data->>'likelihoodScore')::INTEGER,
        affected_count
      );

      -- Insert finding
      INSERT INTO findings (
        scan_id,
        organization_id,
        rule_id,
        rule_name,
        category,
        severity,
        title,
        description,
        affected_objects,
        remediation,
        external_references,
        risk_score,
        impact_score,
        likelihood_score
      )
      VALUES (
        scan_id,
        p_org_id,
        finding_data->>'ruleId',
        finding_data->>'ruleName',
        finding_data->>'category',
        (finding_data->>'severity')::severity_enum,
        finding_data->>'title',
        finding_data->>'description',
        COALESCE(finding_data->'affectedObjects', '[]'::JSONB),
        finding_data->>'remediation',
        COALESCE(finding_data->'references', '[]'::JSONB),
        calculated_risk_score,
        (finding_data->>'impactScore')::INTEGER,
        (finding_data->>'likelihoodScore')::INTEGER
      );
    END LOOP;
  END IF;

  -- Update scan status to completed
  UPDATE scans 
  SET 
    status = 'completed',
    completed_at = NOW(),
    processing_duration = NOW() - started_at,
    findings_summary = json_build_object(
      'total', (SELECT COUNT(*) FROM findings WHERE scan_id = scan_id),
      'critical', (SELECT COUNT(*) FROM findings WHERE scan_id = scan_id AND severity = 'critical'),
      'high', (SELECT COUNT(*) FROM findings WHERE scan_id = scan_id AND severity = 'high'),
      'medium', (SELECT COUNT(*) FROM findings WHERE scan_id = scan_id AND severity = 'medium'),
      'low', (SELECT COUNT(*) FROM findings WHERE scan_id = scan_id AND severity = 'low')
    )
  WHERE id = scan_id;

  -- Trigger real-time notification (will be handled by triggers)
  PERFORM pg_notify('scan_completed', json_build_object('scan_id', scan_id, 'organization_id', p_org_id)::text);

  RETURN scan_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Get scan statistics for organization
CREATE OR REPLACE FUNCTION get_scan_statistics(org_id UUID, days_back INTEGER DEFAULT 90)
RETURNS JSON AS $$
DECLARE
  result JSON;
BEGIN
  SELECT json_build_object(
    'total_scans', COUNT(*),
    'completed_scans', COUNT(*) FILTER (WHERE status = 'completed'),
    'failed_scans', COUNT(*) FILTER (WHERE status = 'failed'),
    'average_duration', COALESCE(AVG(EXTRACT(epoch FROM processing_duration)), 0),
    'scan_frequency', json_build_object(
      'daily_average', COUNT(*) / GREATEST(days_back, 1),
      'weekly_average', COUNT(*) / GREATEST(days_back / 7, 1),
      'monthly_average', COUNT(*) / GREATEST(days_back / 30, 1)
    ),
    'scan_types_distribution', json_object_agg(scan_type, count_by_type)
  )
  INTO result
  FROM (
    SELECT 
      status,
      processing_duration,
      scan_type,
      COUNT(*) OVER (PARTITION BY scan_type) as count_by_type
    FROM scans
    WHERE organization_id = org_id
      AND created_at > NOW() - (days_back || ' days')::INTERVAL
  ) scan_stats;
  
  RETURN result;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create materialized view for dashboard performance
CREATE MATERIALIZED VIEW dashboard_metrics AS
SELECT 
  s.organization_id,
  COUNT(DISTINCT s.id) as total_scans,
  COALESCE(AVG(s.overall_score), 0)::INTEGER as avg_security_score,
  COUNT(DISTINCT s.id) FILTER (WHERE s.created_at > NOW() - INTERVAL '30 days') as recent_scans,
  COUNT(f.id) FILTER (WHERE f.severity = 'critical' AND f.status = 'open') as critical_findings,
  COUNT(f.id) FILTER (WHERE f.severity = 'high' AND f.status = 'open') as high_findings,
  COUNT(f.id) FILTER (WHERE f.severity = 'medium' AND f.status = 'open') as medium_findings,
  COUNT(f.id) FILTER (WHERE f.severity = 'low' AND f.status = 'open') as low_findings,
  MAX(s.created_at) as last_scan_date,
  COUNT(f.id) FILTER (WHERE f.status = 'resolved') as resolved_findings
FROM scans s
LEFT JOIN findings f ON s.id = f.scan_id
WHERE s.status = 'completed'
GROUP BY s.organization_id;

-- Create index on materialized view
CREATE UNIQUE INDEX ON dashboard_metrics(organization_id);

-- Function to refresh materialized view
CREATE OR REPLACE FUNCTION refresh_dashboard_metrics()
RETURNS VOID AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY dashboard_metrics;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute permissions
GRANT EXECUTE ON FUNCTION calculate_org_security_score(UUID, INTEGER) TO authenticated;
GRANT EXECUTE ON FUNCTION get_findings_trend(UUID, INTEGER) TO authenticated;
GRANT EXECUTE ON FUNCTION calculate_finding_risk_score(severity_enum, INTEGER, INTEGER, INTEGER) TO authenticated;
GRANT EXECUTE ON FUNCTION get_organization_dashboard_summary(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION process_desktop_scan(UUID, UUID, TEXT, scan_type_enum, JSONB) TO authenticated;
GRANT EXECUTE ON FUNCTION get_scan_statistics(UUID, INTEGER) TO authenticated;
GRANT EXECUTE ON FUNCTION refresh_dashboard_metrics() TO authenticated;

-- Grant select permissions on materialized view
GRANT SELECT ON dashboard_metrics TO authenticated;

-- Add helpful comments
COMMENT ON FUNCTION calculate_org_security_score(UUID, INTEGER) IS 'Calculate average security score for organization over specified days';
COMMENT ON FUNCTION get_findings_trend(UUID, INTEGER) IS 'Get trending data for findings by severity over time';
COMMENT ON FUNCTION calculate_finding_risk_score(severity_enum, INTEGER, INTEGER, INTEGER) IS 'Calculate weighted risk score for individual findings';
COMMENT ON FUNCTION get_organization_dashboard_summary(UUID) IS 'Get comprehensive dashboard data for organization';
COMMENT ON FUNCTION process_desktop_scan(UUID, UUID, TEXT, scan_type_enum, JSONB) IS 'Process uploaded scan data from desktop application';
COMMENT ON FUNCTION get_scan_statistics(UUID, INTEGER) IS 'Get statistical analysis of scans for organization';

COMMENT ON MATERIALIZED VIEW dashboard_metrics IS 'Pre-calculated dashboard metrics for improved query performance';