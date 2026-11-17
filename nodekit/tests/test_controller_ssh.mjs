import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,chmodSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {PassThrough} from 'node:stream';
import {EventEmitter} from 'node:events';
import {checkedSshTarget,deliverSignedNodeAccess,NodekitTransportError}
  from '../controller-ssh.mjs';

test('strict SSH target protects existing production and RFC1918 nodes',()=>{
  for(const ip of [
    '89.125.90.101','188.120.254.223','127.0.0.1',
    '192.168.1.1','10.0.0.1','203.0.113.10','::1',
  ]){
    assert.throws(()=>checkedSshTarget('new-node.example.net',ip,'de-node-99'),
      NodekitTransportError);
  }
  for(const host of ['x;echo bad','-ssh.example.net','host..example.net']){
    assert.throws(()=>checkedSshTarget(host,'1.1.1.1','de-node-99'),
      NodekitTransportError);
  }
  assert.deepEqual(checkedSshTarget('new-node.example.net',
    '1.1.1.1','de-node-99'),{
      host:'new-node.example.net',ip:'1.1.1.1',nodeId:'de-node-99',
    });
});

test('signed command travels via pinned noninteractive SSH without logging key',async()=>{
  const folder=mkdtempSync(join(tmpdir(),'nodekit-controller-'));
  try{
    const key=join(folder,'id_key'),known=join(folder,'known_hosts');
    writeFileSync(key,'test-only-private-key',{mode:0o600});
    writeFileSync(known,'new-node.example.net test-only',{mode:0o600});
    chmodSync(key,0o600);chmodSync(known,0o600);
    const nodeId='de-node-99';
    const cmd={
      nodeId,op:'inspect',id:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      revision:null,enabled:null,expiresAt:null,issuedAt:'2026-11-17T13:00:00.000Z',
      nonce:'a'.repeat(64),signature:'B'.repeat(86),
    };
    let capturedArgs,capturedBody='';
    function fakeSpawn(exe,args,options){
      assert.equal(exe,'ssh');
      assert.deepEqual(options.stdio,['pipe','pipe','pipe']);
      capturedArgs=args;
      const proc=new EventEmitter();
      proc.stdin=new PassThrough();
      proc.stdout=new PassThrough();
      proc.stderr=new PassThrough();
      proc.kill=()=>{};
      proc.stdin.on('data',chunk=>{capturedBody+=chunk.toString();});
      proc.stdin.on('finish',()=>{
        queueMicrotask(()=>{
          proc.stdout.write('{"ok":true,"result":{"revision":0,"enabled":false}}\n');
          proc.emit('close',0);
        });
      });
      return proc;
    }
    const result=await deliverSignedNodeAccess({
      host:'new-node.example.net',ip:'1.1.1.1',nodeId,
      identityFile:key,knownHostsFile:known,command:cmd,
      spawnProcess:fakeSpawn,
    });
    assert.equal(result.enabled,false);
    assert.ok(capturedArgs.includes('HostName=1.1.1.1'));
    assert.ok(capturedArgs.includes('HostKeyAlias=new-node.example.net'));
    assert.ok(capturedArgs.includes('StrictHostKeyChecking=yes'));
    assert.ok(capturedArgs.includes('BatchMode=yes'));
    assert.equal(JSON.parse(capturedBody).nonce,cmd.nonce);
    assert.ok(!capturedArgs.join(' ').includes(cmd.nonce));
    assert.ok(!capturedArgs.join(' ').includes(cmd.signature));
    chmodSync(key,0o644);
    await assert.rejects(deliverSignedNodeAccess({
      host:'new-node.example.net',ip:'1.1.1.1',nodeId,
      identityFile:key,knownHostsFile:known,command:cmd,
      spawnProcess:fakeSpawn,
    }),NodekitTransportError);
  }finally{
    rmSync(folder,{recursive:true,force:true});
  }
});
