import type {EditingContent,SaveResult} from '../api/editingApi';
export type SaveState='CONFIRMED'|'CHECKING'|'NOT_SAVED'|'CONFLICT'|'EXPIRED'|'UNKNOWN';
export function confirmedSaveState(result:SaveResult):SaveState {
  return result.state==='UNVERIFIABLE'||result.state==='UNAVAILABLE'?'UNKNOWN':result.state;
}
export const saveLabels:Record<SaveState,string>={CONFIRMED:'저장 확인됨',CHECKING:'저장 확인 중',NOT_SAVED:'저장되지 않음',CONFLICT:'다른 변경과 충돌',EXPIRED:'Workspace 만료',UNKNOWN:'저장 결과 확인 불가'};
export async function editedHash(text:string,content:EditingContent):Promise<string>{
 let value=text.replace(/\r\n/g,'\n');if(content.newline==='CRLF')value=value.replace(/\n/g,'\r\n');if(content.bom)value='\ufeff'+value;
 const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value));return [...new Uint8Array(digest)].map(v=>v.toString(16).padStart(2,'0')).join('');
}
