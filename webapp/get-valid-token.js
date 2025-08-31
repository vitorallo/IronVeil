// Get a valid JWT token for testing
const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = 'http://127.0.0.1:54321';
const supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';

async function getValidToken() {
  const supabase = createClient(supabaseUrl, supabaseKey);
  
  const { data: authData, error } = await supabase.auth.signInWithPassword({
    email: 'test2@ironveil.local',
    password: 'nokia347'
  });
  
  if (error) {
    console.error('Auth failed:', error.message);
    return;
  }
  
  console.log('Valid JWT Token:');
  console.log(authData.session.access_token);
}

getValidToken();