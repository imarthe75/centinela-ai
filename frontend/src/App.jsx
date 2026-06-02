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
  // Limpia el ?code=&state= de la URL tras el intercambio exitoso.
  // Sin esto, React.StrictMode ejecuta el callback dos veces y el segundo
  // intento falla con 400 porque el authorization code ya fue usado.
  onSigninCallback: () => {
    window.history.replaceState({}, document.title, window.location.pathname);
  },
};

export default function App() {
  return (
    <AuthProvider {...oidcConfig}>
      <Dashboard />
    </AuthProvider>
  );
}
