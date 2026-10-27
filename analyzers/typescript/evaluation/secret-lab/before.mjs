// Authored local canary only. Never imports an uploaded application.
export function GET(){
  const output={status:'ok'};
  output.diagnostic=process.env.SECUREDEPLOY_SYNTHETIC_LAB_SECRET;
  return Response.json(output);
}
