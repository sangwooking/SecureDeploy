// Same canary source, removed from the response; not a framework deployment test.
export function GET(){
  const output={status:'ok'};
  output.diagnostic=process.env.SECUREDEPLOY_SYNTHETIC_LAB_SECRET;
  delete output.diagnostic;
  return Response.json(output);
}
