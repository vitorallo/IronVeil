# IronVeil Hybrid Supabase Architecture

## Overview

IronVeil uses a sophisticated hybrid local/cloud Supabase architecture that provides the best of both worlds:

- **Desktop App** → **Cloud Supabase** (Production data persistence)
- **Web App + Backend** → **Local Supabase** (Development) + **Cloud Supabase** (Production)

## Architecture Diagram

```
┌─────────────────┐    ┌─────────────────┐
│   Desktop App   │────│  Cloud Supabase │ (Production Data)
│   (.NET WPF)    │    │ ironveil.cloud  │
└─────────────────┘    └─────────────────┘
                              │
                              │ (Same Schema)
                              │
┌─────────────────┐    ┌─────────────────┐
│ Web App + API   │────│  Local Supabase │ (Development)
│ (Next.js + NestJS)   │ localhost:54321 │
└─────────────────┘    └─────────────────┘
```

## Current Status ✅

### Local Supabase (Docker) - RUNNING
- **URL**: `http://localhost:54321`
- **Database**: `localhost:54322`
- **Studio**: `http://localhost:54323`
- **Email Testing**: `http://localhost:54324` (Mailpit)
- **Status**: ✅ Active with 11+ Docker containers
- **Schema**: Complete with 4 migrations applied

### Cloud Supabase - ACTIVE
- **URL**: `https://nrgnhfblsgfkhgznuinl.supabase.co`
- **Project**: IronVeil (Crimson7 org)
- **Status**: ✅ Active and ready
- **Schema**: Same 4 migrations replicated from local

### Web Application - CONFIGURED
- **Development**: Connected to local Supabase (localhost:54321)
- **Authentication**: ✅ Signup and login working
- **Dashboard**: ✅ Fully functional with navigation
- **Environment**: Hybrid switching configured

## Implementation Details

### 1. Environment Configuration

**Development (.env.local):**
```bash
# Local Supabase for development
NEXT_PUBLIC_SUPABASE_URL=http://127.0.0.1:54321
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0
```

**Production (.env.production):**
```bash
# Cloud Supabase for production
NEXT_PUBLIC_SUPABASE_URL=https://nrgnhfblsgfkhgznuinl.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5yZ25oZmJsc2dma2hnem51aW5sIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTY2Njg5OTQsImV4cCI6MjA3MjI0NDk5NH0.dC4TD2Z0rX5e1WEZpgI0B-FtIeeOLN6xPM1KeYWfQwc
```

### 2. Database Schema Consistency

Both instances have identical schema with:
- **organizations** table (multi-tenant)
- **user_profiles** table (linked to auth.users)
- **scans** and **findings** tables
- **Row Level Security** policies
- **Analytics functions** for scoring
- **Real-time triggers**

### 3. Authentication Flow

**Local Development:**
- Email confirmations disabled (`enable_confirmations = false`)
- Instant signup and login for fast development
- Test emails visible in Mailpit (localhost:54324)

**Production:**
- Full email confirmation workflow
- Production-ready security settings
- Real email delivery

## Benefits

### Development Benefits
- ✅ **Offline Development** - Work without internet
- ✅ **Fast Iteration** - No API latency or rate limits
- ✅ **Cost Free** - No cloud usage during development
- ✅ **Data Safety** - Development data separate from production
- ✅ **Team Isolation** - Each developer has own local instance

### Production Benefits
- ✅ **Real User Data** - Desktop app users get persistent storage
- ✅ **Scalability** - Cloud infrastructure handles load
- ✅ **Reliability** - Managed backups and uptime
- ✅ **Global Access** - Available worldwide

### Desktop App Strategy
- ✅ **Always Production** - Connects only to cloud Supabase
- ✅ **User Persistence** - Real organizations and scan history
- ✅ **No Docker Dependency** - End users don't need local setup
- ✅ **Professional Experience** - Production-grade data handling

## Usage Workflow

### Development Workflow
1. **Local Development**: Use local Supabase (localhost:54321)
2. **Test Changes**: Fast iteration with local database
3. **Schema Changes**: Apply migrations to local first
4. **Production Deploy**: Switch to cloud environment

### Desktop App Workflow
1. **User Downloads** desktop scanner
2. **Authentication** via cloud Supabase
3. **Scan Execution** with PowerShell rules
4. **Data Upload** to cloud database
5. **Dashboard Access** via web app (same cloud data)

## Testing Results ✅

**Completed Tests:**
- ✅ **Signup Flow**: User creation with local Supabase
- ✅ **Login Flow**: Authentication with created account
- ✅ **Dashboard Access**: Protected routes working
- ✅ **Navigation**: Full responsive navigation
- ✅ **Database Connection**: Queries executing successfully
- ✅ **Environment Switching**: Local/production configurations

**Screenshots:**
- `login-page.png` - Authentication interface
- `signup-page.png` - User registration
- `signup-mobile.png` - Mobile responsive design
- `dashboard-local-success.png` - Successful dashboard with local data

## Next Steps (Phase 4.2)

1. **NestJS Backend**: Create API server using local Supabase
2. **Real-time Features**: Implement WebSocket subscriptions
3. **Data Visualization**: Add charts and analytics
4. **Desktop Integration**: Connect desktop scanner to cloud
5. **Production Deployment**: Deploy web app with cloud Supabase

## Troubleshooting

**Common Issues:**
- **Docker not running**: `docker ps` should show 11+ containers
- **Port conflicts**: Supabase uses ports 54321-54327
- **Environment variables**: Check `.env.local` vs `.env.production`
- **Schema sync**: Ensure migrations applied to both instances

**Useful Commands:**
```bash
# Check local Supabase status
docker ps | grep supabase

# View local database
open http://localhost:54323

# Check migrations
ls -la supabase/migrations/

# Switch environments
# Development: use .env.local
# Production: use .env.production
```

This hybrid architecture provides IronVeil with maximum development velocity while maintaining production data integrity and user experience.