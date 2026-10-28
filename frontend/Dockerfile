# --- dev: Vite dev server with HMR (only for local development; never expose this to a network) ---
FROM node:26-slim AS dev
WORKDIR /app
COPY package*.json ./
RUN npm install --legacy-peer-deps
COPY . .
RUN useradd -m -u 10001 appuser && chown -R appuser:appuser /app
USER appuser
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

# --- build: compile the static bundle ---
FROM node:26-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm install --legacy-peer-deps
COPY . .
ARG VITE_AUTH_URL
ARG VITE_AUTH_APP_SLUG
ARG VITE_PASSWORD_RECOVERY_URL
ARG VITE_BRAND_NAME
ENV VITE_AUTH_URL=$VITE_AUTH_URL VITE_AUTH_APP_SLUG=$VITE_AUTH_APP_SLUG VITE_PASSWORD_RECOVERY_URL=$VITE_PASSWORD_RECOVERY_URL VITE_BRAND_NAME=$VITE_BRAND_NAME
RUN npm run build

# --- prod (default): static files served by an unprivileged nginx; no Node, no dev server at runtime ---
FROM nginxinc/nginx-unprivileged:alpine AS prod
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
