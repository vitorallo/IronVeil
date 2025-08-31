import { ReactNode } from 'react'
import { Navigation } from './navigation'

interface DashboardLayoutProps {
  children: ReactNode
  user: any
  userProfile: any
}

export function DashboardLayout({ children, user, userProfile }: DashboardLayoutProps) {
  return (
    <div className="min-h-screen bg-gray-50">
      <Navigation user={user} userProfile={userProfile} />
      <main className="mx-auto max-w-7xl px-4 pt-8 pb-16 sm:px-6 lg:px-8">
        {children}
      </main>
    </div>
  )
}