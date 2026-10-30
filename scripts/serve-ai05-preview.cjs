// Isolated preview reverse proxy only. Production server, origin policy and data remain untouched.
const http=require('node:http'),fs=require('node:fs'),path=require('node:path');
const root=fs.realpathSync(process.argv[2]||'/private/tmp/securedeploy-ai05-preview/dist');
if(!root.startsWith('/private/tmp/securedeploy-ai05-preview/'))throw Error('ISOLATED_BUILD_REQUIRED');
const port=5191,backend=58044,origins=new Set(['http://127.0.0.1:5191','http://localhost:5191']);
const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'};
const server=http.createServer((req,res)=>{
 if(!['127.0.0.1:5191','localhost:5191'].includes(req.headers.host)||req.headers.origin&&!origins.has(req.headers.origin)){res.writeHead(403);res.end();return;}
 const url=new URL(req.url,'http://127.0.0.1:5191');
 if(url.pathname.startsWith('/api/')){const headers={...req.headers,host:'127.0.0.1:'+backend};if(headers.origin)headers.origin='http://localhost:5173';
  const outgoing=http.request({hostname:'127.0.0.1',port:backend,method:req.method,path:url.pathname+url.search,headers},r=>{res.writeHead(r.statusCode,r.headers);r.pipe(res);});outgoing.on('error',()=>{if(!res.headersSent)res.writeHead(502,{'Content-Type':'application/json'});res.end('{"message":"격리 Backend에 연결할 수 없습니다."}');});req.pipe(outgoing);return;
 }
 if(!['GET','HEAD'].includes(req.method)){res.writeHead(405);res.end();return;}
 let file;try{file=fs.realpathSync(path.resolve(root,'.'+decodeURIComponent(url.pathname==='/'?'/index.html':url.pathname)));}catch{res.writeHead(404);res.end();return;}
 if(!file.startsWith(root+path.sep)||!fs.statSync(file).isFile()){res.writeHead(403);res.end();return;}
 res.writeHead(200,{'Content-Type':types[path.extname(file)]||'application/octet-stream','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});if(req.method==='HEAD')res.end();else fs.createReadStream(file).pipe(res);
});server.listen(port,'127.0.0.1',()=>console.log('AI05_ISOLATED_PREVIEW http://127.0.0.1:5191 MOCK_ONLY backend=58044'));
process.on('SIGTERM',()=>server.close(()=>process.exit(0)));
