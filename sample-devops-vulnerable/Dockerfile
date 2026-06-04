FROM node:latest

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .

ENV API_KEY=prod_api_key_1234567890
ENV SECRET=container_secret_abcdef123456
ENV PASSWORD=super-secret-password

EXPOSE 3000
CMD ["node", "server.js"]
