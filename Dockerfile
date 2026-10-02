FROM node:22.21.1-alpine AS build
RUN corepack enable && corepack prepare yarn@1.22.19 --activate
WORKDIR /app
COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile
COPY tsconfig.json tsconfig.build.json ./
COPY knexfile.ts ./
COPY db ./db
COPY scripts ./scripts
COPY src ./src
RUN yarn build

FROM node:22.21.1-alpine AS runtime
RUN corepack enable && corepack prepare yarn@1.22.19 --activate
ENV NODE_ENV=production
WORKDIR /app
COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile --production=true && yarn cache clean
COPY --from=build /app/dist ./dist
USER node
EXPOSE 3001
CMD ["node", "dist/src/server.js"]
