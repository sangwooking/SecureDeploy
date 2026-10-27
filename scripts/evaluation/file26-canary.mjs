// Own temporary files only; no acquired project code or upload dependency executes.
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,realpathSync,symlinkSync,rmSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import assert from 'node:assert/strict';
const root=mkdtempSync(path.join(tmpdir(),'securedeploy-owned-file26-'));
try{
 const base=path.join(root,'data'),sibling=path.join(root,'data-other');mkdirSync(base);mkdirSync(sibling);
 writeFileSync(path.join(base,'ok.txt'),'allowed');writeFileSync(path.join(sibling,'canary.txt'),'owned-outside');
 const input='../data-other/canary.txt',unsafe=path.resolve(base,input);
 assert.ok(unsafe.startsWith(base));assert.equal(readFileSync(unsafe,'utf8'),'owned-outside');
 const confined=name=>{
  const p=path.resolve(base,name),rel=path.relative(base,p);
  if(rel.startsWith('..')||path.isAbsolute(rel))throw Error('OUTSIDE');return p;
 };
 assert.throws(()=>confined(input),/OUTSIDE/);
 assert.equal(readFileSync(confined('ok.txt'),'utf8'),'allowed');
 symlinkSync(path.join(sibling,'canary.txt'),path.join(base,'link.txt'));
 assert.equal(readFileSync(confined('link.txt'),'utf8'),'owned-outside');
 const actual=realpathSync(confined('link.txt')),relative=path.relative(realpathSync(base),actual);
 assert.ok(relative.startsWith('..')||path.isAbsolute(relative));
 const store=(filename,bytes)=>{
  if(!filename.toLowerCase().endsWith('.png'))throw Error('TYPE');
  if(bytes.length>32)throw Error('SIZE');
  if(!bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])))throw Error('SIGNATURE');
  const target=path.join(base,randomUUID()+'.bin');writeFileSync(target,bytes);return target;
 };
 const fixture=Buffer.from([137,80,78,71,13,10,26,10,0]);
 const saved=store('../../original.PNG',fixture);assert.equal(path.dirname(saved),base);assert.deepEqual(readFileSync(saved),fixture);
 assert.throws(()=>store('image.png',Buffer.from('not-image')),/SIGNATURE/);
 assert.throws(()=>store('image.png',Buffer.alloc(33)),/SIZE/);
 assert.throws(()=>store('image.png.exe',fixture),/TYPE/);
 assert.notEqual(path.posix.basename('C:\\folder\\name'),path.win32.basename('C:\\folder\\name'));
 console.log(JSON.stringify({directoryEscapeObserved:true,prefixNotContainment:true,relativeGuardRejectsEscape:true,
  normalReadPreserved:true,lexicalGuardDoesNotStopSymlink:true,realpathDetectsOwnedSymlinkEscape:true,
  serverGeneratedNamePreservesBytes:true,extensionSignatureAndSizeControlsReject:true,
  windowsPosixDifferenceObserved:true,fullImageValidation:false,toctouProtectionVerified:false,targetAppExecuted:false}));
}finally{rmSync(root,{recursive:true,force:true});assert.equal(existsSync(root),false);}
