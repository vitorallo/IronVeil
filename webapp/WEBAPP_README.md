# IronVeil Web Application

Frontend web application for the IronVeil Identity Security Platform built with Next.js 14, React 18, TailwindCSS, and shadcn/ui.

## Features

- ✅ **Authentication**: Supabase Auth integration with JWT tokens
- ✅ **Protected Routes**: Middleware-based route protection
- ✅ **Responsive Design**: Mobile-first design with TailwindCSS
- ✅ **Component Library**: shadcn/ui components for consistent UI
- ✅ **Multi-tenant**: Organization-based data isolation
- ✅ **Dashboard**: Real-time security scan results display
- ✅ **TypeScript**: Full type safety throughout

## Setup

### Environment Variables

Copy `.env.local` and configure your Supabase credentials:

```bash
# Supabase Configuration
NEXT_PUBLIC_SUPABASE_URL=your-supabase-url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-supabase-anon-key

# Application Configuration  
NEXT_PUBLIC_APP_NAME=IronVeil
NEXT_PUBLIC_APP_VERSION=1.0.0
```

### Development

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

## Architecture

### Project Structure

```
src/
├── app/                    # Next.js App Router pages
│   ├── dashboard/         # Main dashboard page
│   ├── login/            # Authentication pages
│   ├── signup/           
│   └── page.tsx          # Root redirect
├── components/
│   ├── dashboard/        # Dashboard-specific components
│   │   ├── layout.tsx   # Main layout wrapper
│   │   └── navigation.tsx # Navigation bar
│   └── ui/              # shadcn/ui components
├── lib/
│   └── supabase/        # Supabase client configuration
├── types/
│   └── database.ts      # Database TypeScript types
└── middleware.ts        # Auth middleware
```

### Authentication Flow

1. **Middleware**: Checks authentication status on all routes
2. **Protected Routes**: Automatically redirects to `/login` if not authenticated
3. **Supabase Auth**: Handles JWT tokens and user sessions
4. **Profile Integration**: Links to user_profiles table for organization data

### Multi-tenant Architecture

- **Organizations**: Each user belongs to an organization (community/enterprise tier)
- **Row Level Security**: Database-level isolation using Supabase RLS
- **User Profiles**: Extended user data with organization relationships

## Integration with Backend

Ready for Phase 4.2 NestJS backend integration:

- ✅ Supabase client configured for database access
- ✅ TypeScript types aligned with database schema
- ✅ Authentication middleware for protected routes
- ✅ Dashboard layout ready for scan data display
- ✅ Component architecture for data visualization

## Next Steps (Phase 4.2)

1. **Backend API**: Create NestJS backend for scan uploads
2. **API Integration**: Connect frontend to REST endpoints
3. **Real-time Updates**: Implement WebSocket/Supabase subscriptions
4. **Data Visualization**: Add charts and analytics components
5. **File Upload**: Handle scan result uploads from desktop scanner