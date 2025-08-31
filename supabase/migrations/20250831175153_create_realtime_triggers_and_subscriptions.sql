-- IronVeil MicroSaaS Real-time Subscriptions & Triggers
-- Phase 1.1: Real-time Dashboard Updates
-- Development Environment: Mac Primary

-- Enable real-time for relevant tables
ALTER publication supabase_realtime ADD TABLE scans;
ALTER publication supabase_realtime ADD TABLE findings;
-- Note: dashboard_metrics is a materialized view and cannot be added to publications

-- Create function to notify scan updates
CREATE OR REPLACE FUNCTION notify_scan_update()
RETURNS TRIGGER AS $$
BEGIN
  -- Notify for scan status changes
  PERFORM pg_notify(
    'scan_updates',
    json_build_object(
      'scan_id', NEW.id,
      'organization_id', NEW.organization_id,
      'status', NEW.status,
      'progress', COALESCE(NEW.metadata->>'progress', '0'),
      'overall_score', NEW.overall_score,
      'event_type', TG_OP,
      'timestamp', NOW()
    )::text
  );
  
  -- If scan completed, also refresh dashboard metrics
  IF NEW.status = 'completed' AND (OLD.status IS NULL OR OLD.status != 'completed') THEN
    -- Trigger dashboard metrics refresh
    PERFORM refresh_dashboard_metrics();
    
    -- Notify dashboard update
    PERFORM pg_notify(
      'dashboard_updates',
      json_build_object(
        'organization_id', NEW.organization_id,
        'event_type', 'scan_completed',
        'scan_id', NEW.id,
        'timestamp', NOW()
      )::text
    );
  END IF;
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to notify findings updates
CREATE OR REPLACE FUNCTION notify_findings_update()
RETURNS TRIGGER AS $$
BEGIN
  -- Notify for new findings or status changes
  PERFORM pg_notify(
    'findings_updates',
    json_build_object(
      'finding_id', NEW.id,
      'scan_id', NEW.scan_id,
      'organization_id', NEW.organization_id,
      'severity', NEW.severity,
      'status', NEW.status,
      'event_type', TG_OP,
      'timestamp', NOW()
    )::text
  );
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to handle automatic updates
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create function to handle scan progress updates
CREATE OR REPLACE FUNCTION handle_scan_progress()
RETURNS TRIGGER AS $$
BEGIN
  -- Update scan progress based on metadata changes
  IF (NEW.metadata->>'progress' IS DISTINCT FROM OLD.metadata->>'progress') THEN
    PERFORM pg_notify(
      'scan_progress',
      json_build_object(
        'scan_id', NEW.id,
        'organization_id', NEW.organization_id,
        'progress', NEW.metadata->>'progress',
        'current_step', NEW.metadata->>'currentStep',
        'timestamp', NOW()
      )::text
    );
  END IF;
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create triggers for scan updates
CREATE TRIGGER scan_update_trigger
  AFTER INSERT OR UPDATE ON scans
  FOR EACH ROW
  EXECUTE FUNCTION notify_scan_update();

CREATE TRIGGER scan_progress_trigger
  AFTER UPDATE ON scans
  FOR EACH ROW
  WHEN (NEW.metadata IS DISTINCT FROM OLD.metadata)
  EXECUTE FUNCTION handle_scan_progress();

-- Create triggers for findings updates
CREATE TRIGGER findings_update_trigger
  AFTER INSERT OR UPDATE ON findings
  FOR EACH ROW
  EXECUTE FUNCTION notify_findings_update();

-- Create triggers for updated_at timestamps
CREATE TRIGGER update_organizations_updated_at
  BEFORE UPDATE ON organizations
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_profiles_updated_at
  BEFORE UPDATE ON user_profiles
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scans_updated_at
  BEFORE UPDATE ON scans
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_findings_updated_at
  BEFORE UPDATE ON findings
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_api_keys_updated_at
  BEFORE UPDATE ON api_keys
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- Create function to handle user profile creation from auth
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
  user_email TEXT;
BEGIN
  -- Get email from auth metadata
  user_email := NEW.email;
  
  -- Only create profile if email exists
  IF user_email IS NOT NULL THEN
    INSERT INTO public.user_profiles (
      id,
      email,
      full_name,
      role,
      created_at
    )
    VALUES (
      NEW.id,
      user_email,
      COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name'),
      'user',
      NOW()
    )
    ON CONFLICT (id) DO NOTHING;
  END IF;
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to validate scan data before processing
CREATE OR REPLACE FUNCTION validate_scan_data()
RETURNS TRIGGER AS $$
BEGIN
  -- Validate required fields in raw_data
  IF NEW.raw_data IS NULL OR NEW.raw_data = '{}'::JSONB THEN
    RAISE EXCEPTION 'Scan raw_data cannot be empty';
  END IF;
  
  -- Validate scan name
  IF LENGTH(TRIM(NEW.name)) = 0 THEN
    RAISE EXCEPTION 'Scan name cannot be empty';
  END IF;
  
  -- Set default started_at if not provided
  IF NEW.started_at IS NULL AND NEW.status != 'pending' THEN
    NEW.started_at = NOW();
  END IF;
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for scan validation
CREATE TRIGGER validate_scan_trigger
  BEFORE INSERT OR UPDATE ON scans
  FOR EACH ROW
  EXECUTE FUNCTION validate_scan_data();

-- Create function to handle organization metrics updates
CREATE OR REPLACE FUNCTION handle_organization_metrics_update()
RETURNS TRIGGER AS $$
BEGIN
  -- Schedule dashboard metrics refresh for the organization
  PERFORM pg_notify(
    'refresh_metrics',
    json_build_object(
      'organization_id', NEW.organization_id,
      'timestamp', NOW()
    )::text
  );
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to generate audit trail
CREATE OR REPLACE FUNCTION create_audit_log(
  table_name TEXT,
  record_id UUID,
  action TEXT,
  old_data JSONB DEFAULT NULL,
  new_data JSONB DEFAULT NULL,
  user_id UUID DEFAULT NULL
)
RETURNS VOID AS $$
BEGIN
  -- This would normally insert into an audit table
  -- For now, we'll just notify
  PERFORM pg_notify(
    'audit_log',
    json_build_object(
      'table_name', table_name,
      'record_id', record_id,
      'action', action,
      'old_data', old_data,
      'new_data', new_data,
      'user_id', COALESCE(user_id, auth.uid()),
      'timestamp', NOW()
    )::text
  );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to handle real-time scan status broadcasting
CREATE OR REPLACE FUNCTION broadcast_scan_status()
RETURNS TRIGGER AS $$
DECLARE
  channel TEXT;
  payload JSON;
BEGIN
  -- Create organization-specific channel
  channel := 'org_' || NEW.organization_id || '_scans';
  
  -- Create payload with scan status
  payload := json_build_object(
    'scan_id', NEW.id,
    'name', NEW.name,
    'status', NEW.status,
    'overall_score', NEW.overall_score,
    'progress', NEW.metadata->>'progress',
    'started_at', NEW.started_at,
    'completed_at', NEW.completed_at,
    'event_type', TG_OP
  );
  
  -- Broadcast to organization-specific channel
  PERFORM pg_notify(channel, payload::text);
  
  -- Also broadcast to global scan channel for admin monitoring
  PERFORM pg_notify('all_scans', payload::text);
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create trigger for real-time scan broadcasting
CREATE TRIGGER broadcast_scan_status_trigger
  AFTER INSERT OR UPDATE ON scans
  FOR EACH ROW
  EXECUTE FUNCTION broadcast_scan_status();

-- Grant necessary permissions
GRANT EXECUTE ON FUNCTION notify_scan_update() TO authenticated;
GRANT EXECUTE ON FUNCTION notify_findings_update() TO authenticated;
GRANT EXECUTE ON FUNCTION handle_scan_progress() TO authenticated;
GRANT EXECUTE ON FUNCTION validate_scan_data() TO authenticated;
GRANT EXECUTE ON FUNCTION create_audit_log(TEXT, UUID, TEXT, JSONB, JSONB, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION broadcast_scan_status() TO authenticated;

-- Add helpful comments
COMMENT ON FUNCTION notify_scan_update() IS 'Triggers real-time notifications when scans are updated';
COMMENT ON FUNCTION notify_findings_update() IS 'Triggers real-time notifications when findings are updated';
COMMENT ON FUNCTION handle_scan_progress() IS 'Handles real-time scan progress updates';
COMMENT ON FUNCTION validate_scan_data() IS 'Validates scan data before insert/update';
COMMENT ON FUNCTION create_audit_log(TEXT, UUID, TEXT, JSONB, JSONB, UUID) IS 'Creates audit log entries for important changes';
COMMENT ON FUNCTION broadcast_scan_status() IS 'Broadcasts scan status changes to organization-specific channels';

-- Create indexes to support real-time queries
CREATE INDEX idx_scans_realtime ON scans(organization_id, status, created_at DESC) WHERE status IN ('processing', 'pending');
CREATE INDEX idx_findings_realtime ON findings(organization_id, status, created_at DESC) WHERE status = 'open';

-- Final notification that setup is complete
SELECT pg_notify('setup_complete', json_build_object(
  'message', 'Real-time triggers and subscriptions setup complete',
  'timestamp', NOW()
)::text);