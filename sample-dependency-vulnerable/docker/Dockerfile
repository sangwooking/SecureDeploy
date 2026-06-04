FROM ubuntu:18.04 AS base
RUN apt-get update && apt-get install -y curl

FROM node:latest AS web
WORKDIR /app
COPY frontend/package.json ./package.json
CMD ["node", "server.js"]
