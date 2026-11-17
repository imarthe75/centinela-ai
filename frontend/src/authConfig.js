// Silent session renewal needs a refresh token, which Authentik only issues when the provider has the offline_access scope mapping.
// Enabled at build time (VITE_AUTH_OFFLINE_ACCESS=true) once that mapping exists; otherwise an expired session re-runs the SSO redirect.
export const OFFLINE_ACCESS = String(import.meta.env.VITE_AUTH_OFFLINE_ACCESS || '').toLowerCase() === 'true';
