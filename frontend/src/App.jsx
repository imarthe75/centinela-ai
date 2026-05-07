import React, { useEffect } from 'react'
import { AuthProvider, useAuth } from 'react-oidc-context'
import { Log } from 'oidc-client-ts'
import LoginPage from './components/LoginPage'
import Dashboard from './components/Dashboard'

// Enable OIDC logging for debugging
Log.setLogger(console);
Log.setLevel(Log.DEBUG);

const oidcConfig = {
  authority: window.location.origin + "/application/o/centinela-cai/",
  client_id: "centinela-cai",
  client_secret: "casmarts_secret_2026",
  redirect_uri: window.location.origin + "/centinela/",
  post_logout_redirect_uri: window.location.origin + "/centinela/",
  response_type: "code",
  scope: "openid profile email",
  automaticSilentRenew: false,
  monitorSession: false,
  loadUserInfo: true,
  onSigninCallback: () => {
    window.history.replaceState({}, document.title, window.location.pathname);
  }
}

function AppContent() {
  const auth = useAuth()

  useEffect(() => {
    console.log("Centinela Auth State:", {
      isLoading: auth.isLoading,
      isAuthenticated: auth.isAuthenticated,
      error: auth.error?.message,
      user: auth.user?.profile?.name
    });
  }, [auth.isLoading, auth.isAuthenticated, auth.error, auth.user]);

  if (auth.isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#002A4C]">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-white"></div>
      </div>
    )
  }

  if (!auth.isAuthenticated) {
    return <LoginPage />
  }

  return <Dashboard />
}

export default function App() {
  return (
    <AuthProvider {...oidcConfig}>
      <AppContent />
    </AuthProvider>
  )
}
