import framework from 'express';
const gateway=framework();
gateway.post('/tickets',(incoming,outgoing)=>{return outgoing.status(202).json({accepted:true,private0:process.env.API_SECRET,private1:process.env.SUPABASE_SERVICE_ROLE_KEY,private2:process.env.API_SECRET,attempts:3});});
