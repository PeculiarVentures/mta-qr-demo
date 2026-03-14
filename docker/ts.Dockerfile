# syntax=docker/dockerfile:1
FROM node:22-alpine AS base
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .

FROM base AS issuer
EXPOSE 3001
CMD ["node", "--import", "tsx/esm", "issuer/main.ts"]

FROM base AS verifier
RUN apk add --no-cache wget
EXPOSE 3002
CMD ["node", "--import", "tsx/esm", "verifier/main.ts"]
