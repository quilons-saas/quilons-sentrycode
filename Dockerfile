FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci
COPY src ./src
COPY migrations ./migrations
COPY ui ./ui
COPY compliance ./compliance
COPY integrations ./integrations
COPY docs ./docs
COPY README.md ./
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
RUN addgroup -S sentrycode && adduser -S -G sentrycode sentrycode
COPY --from=build --chown=sentrycode:sentrycode /app/package.json /app/package-lock.json ./
COPY --from=build --chown=sentrycode:sentrycode /app/node_modules ./node_modules
COPY --from=build --chown=sentrycode:sentrycode /app/dist ./dist
COPY --from=build --chown=sentrycode:sentrycode /app/ui ./ui
COPY --from=build --chown=sentrycode:sentrycode /app/migrations ./migrations
COPY --from=build --chown=sentrycode:sentrycode /app/compliance ./compliance
COPY --from=build --chown=sentrycode:sentrycode /app/integrations ./integrations
COPY --from=build --chown=sentrycode:sentrycode /app/docs ./docs
COPY --from=build --chown=sentrycode:sentrycode /app/README.md ./
RUN mkdir -p /app/.sentrycode && chown -R sentrycode:sentrycode /app/.sentrycode
USER sentrycode
EXPOSE 7787
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 CMD node -e "fetch('http://127.0.0.1:7787/api/v1/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node","dist/cli/main.js","serve",".","--tenant","standalone","--project","default","--host","0.0.0.0","--port","7787"]
