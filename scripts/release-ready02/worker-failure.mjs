// Controlled failure injection only; never a release Worker.
await new Promise(r=>setTimeout(r,750));process.exit(86);
