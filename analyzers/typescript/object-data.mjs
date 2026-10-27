// Own data properties of bounded object literals only, never getters/proxies or target execution.
export function objectData({tick,note,step,loc,sources}){
 const allowed=key=>typeof key==='string'&&key.length<=80&&!['__proto__','prototype','constructor','toJSON'].includes(key);
 const plain=v=>v?.tag==='object'&&v.ref?.plainData&&!v.unknown&&!v.ref.unknown&&v.ref.properties.size<=32;
 function write(receiver,key,v,state,node){
  if(!plain(receiver)||key?.tag!=='constant'||!allowed(String(key.constant))||!sources(receiver).length&&!sources(v).length)return false;
  const ref=state.forkRefs?.get(receiver.ref)??receiver.ref;
  if(!ref.properties.has(String(key.constant))&&ref.properties.size>=32){
   ref.unknown=true;ref.exposureUnknownSources=[...(ref.exposureUnknownSources??[]),...sources(v)].slice(0,20);
   note(state.mod,'OBJECT_DATA_PROPERTY_LIMIT');return true;
  }
  ref.properties.set(String(key.constant),step(v,loc(node,state.mod,'OBJECT_DATA_PROPERTY_WRITE',state.fn),state.mod));
  return true;
 }
 function remove(receiver,key,state){
  const ref=state.forkRefs?.get(receiver?.ref)??receiver?.ref;
  if(state.nodeMode&&ref?.nodeIdentity)state.nodeMutations?.add(ref.nodeIdentity);
  if(ref?.mongooseTracked)ref.mongooseRevision=(ref.mongooseRevision??0)+1;
  if(plain(receiver)&&sources(receiver).length&&key?.tag==='constant'&&allowed(String(key.constant))){ref.properties.delete(String(key.constant));return true;}
  if(ref)ref.unknown=true;
  note(state.mod,'OBJECT_DELETE_UNRESOLVED');return false;
 }
 return {allowed,plain,write,remove};
}
