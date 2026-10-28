import React from 'react';
import { AuthProvider } from 'react-oidc-context';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 10_000, refetchOnWindowFocus: false, retry: 1 } } });
import Dashboard from './components/Dashboard';

const currentOrigin = typeof window !== 'undefined' && window.location ? window.location.origin : "http://localhost";

const IDP = (import.meta.env.VITE_AUTH_URL || 'https://auth.example.internal').replace(/\/$/, '');
const APP_SLUG = import.meta.env.VITE_AUTH_APP_SLUG || 'centinela-ai';

const oidcConfig = {
  authority: `${IDP}/application/o/${APP_SLUG}/`,
  client_id: "centinela-ai",
  redirect_uri: currentOrigin.endsWith('/') ? currentOrigin : currentOrigin + '/',
  post_logout_redirect_uri: currentOrigin.endsWith('/') ? currentOrigin : currentOrigin + '/',
  response_type: "code",
  scope: "openid profile email",
  automaticSilentRenew: false,
  metadata: {
    issuer: `${IDP}/application/o/${APP_SLUG}/`,
    authorization_endpoint: `${IDP}/application/o/authorize/`,
    token_endpoint: `${IDP}/application/o/token/`,
    userinfo_endpoint: `${IDP}/application/o/userinfo/`,
    end_session_endpoint: `${IDP}/application/o/${APP_SLUG}/end-session/`,
    jwks_uri: `${IDP}/application/o/${APP_SLUG}/jwks/`,
  },
  // Limpia el ?code=&state= de la URL tras el intercambio exitoso.
  // Sin esto, React.StrictMode ejecuta el callback dos veces y el segundo
  // intento falla con 400 porque el authorization code ya fue usado.
  onSigninCallback: () => {
    window.history.replaceState({}, document.title, window.location.pathname);
  },
};

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider {...oidcConfig}>
          <Dashboard />
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
