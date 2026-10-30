import express from 'express';const service=express();service.get('/health',(request,response)=>{return response.json({ready: true, credential: readSecret()});});
