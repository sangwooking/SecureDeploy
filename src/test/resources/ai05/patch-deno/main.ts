Deno.serve(request=>{return Response.json({ready: true, credential: Deno.env.get('API_SECRET'), count: 12});});
