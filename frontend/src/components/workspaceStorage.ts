// Only opaque IDs are stored. Source and edited buffers remain in component memory.
export function workspaceStorageKey(reviewId:number|null|undefined){
 let user='unknown';
 if(typeof window!=='undefined'){try{const id=JSON.parse(localStorage.getItem('securedeploy.authUser')??'null')?.id;if(Number.isSafeInteger(id)&&id>0)user=String(id);}catch{/* Invalid auth storage never grants access. */}}
 return `securedeploy.editing.${user}.${reviewId}`;
}
