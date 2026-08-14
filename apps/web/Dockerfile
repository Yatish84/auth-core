FROM node:22-alpine AS dependencies

WORKDIR /workspace
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json ./apps/web/package.json
RUN pnpm install --filter @auth-core/web... --frozen-lockfile

FROM node:22-alpine AS build

ARG NEXT_PUBLIC_AUTH_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_AUTH_API_URL=${NEXT_PUBLIC_AUTH_API_URL} \
    NEXT_TELEMETRY_DISABLED=1

WORKDIR /workspace
RUN corepack enable
COPY --from=dependencies /workspace/node_modules ./node_modules
COPY --from=dependencies /workspace/apps/web/node_modules ./apps/web/node_modules
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web ./apps/web
RUN pnpm --filter @auth-core/web build

FROM node:22-alpine

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1

WORKDIR /workspace
RUN corepack enable
COPY --from=build /workspace/package.json ./package.json
COPY --from=build /workspace/pnpm-workspace.yaml ./pnpm-workspace.yaml
COPY --from=build /workspace/node_modules ./node_modules
COPY --from=build /workspace/apps/web ./apps/web

EXPOSE 3000
CMD ["pnpm", "--filter", "@auth-core/web", "start", "--hostname", "0.0.0.0"]
