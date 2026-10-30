import framework from 'express';
const gateway=framework();
gateway.post('/tickets',(incoming,outgoing)=>{return outgoing.status(202).json({accepted:true,private0:process.env.API_SECRET,attempts:3});});
