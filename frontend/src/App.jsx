import React from 'react';
import { AuthProvider } from 'react-oidc-context';
import Dashboard from './components/Dashboard';

const oidcConfig = {
  authority: "https://auth.casmart.internal/application/o/centinela-ai/",
  client_id: "centinela-ai",
  redirect_uri: "https://centinela.casmart.internal/",
  post_logout_redirect_uri: "https://centinela.casmart.internal/",
  response_type: "code",
  scope: "openid profile email",
};

export default function App() {
  return (
    <AuthProvider {...oidcConfig}>
      <Dashboard />
    </AuthProvider>
  );
}
