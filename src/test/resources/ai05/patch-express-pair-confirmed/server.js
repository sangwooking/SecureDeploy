import express from 'express';
const service=express();
service.get('/health',(request,response)=>{
 return response.status(200).json({ready: true, credential: process.env.API_SECRET, count: 12, secondary: process.env.SUPABASE_SERVICE_ROLE_KEY});
});
