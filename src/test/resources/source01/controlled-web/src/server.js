import express from 'express';
import { status } from './services/status.js';
const app = express();
app.get('/health', (request, response) => {
  return response.status(201).json({ ready: true, credential: process.env.API_SECRET, count: 12 });
});
app.get('/status', status);
const server = app.listen(Number(process.env.SOURCE01_PORT), '127.0.0.1');
process.on('SIGTERM', () => server.close());
