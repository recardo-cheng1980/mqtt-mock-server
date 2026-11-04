'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const tls = require('node:tls');
const mqtt = require('mqtt-packet');
const { spawn, execFileSync } = require('node:child_process');

test('real broker challenges the authenticated device before publishing a commission command', { timeout: 30000 }, async t => {
  const src = path.resolve(__dirname, '..');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'commission-integration-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  for (const name of ['mqtt.js', 'mqtt-client-trust.js', 'operational-client-ca.pem', 'log-tail.js', 'ssh-sign-policy.js', 'ssh-plane-policy.js', 'clamav-api.js', 'commission-readiness.js', 'package.json']) {
    fs.copyFileSync(path.join(src, name), path.join(dir, name));
  }
  fs.symlinkSync(path.join(src, 'node_modules'), path.join(dir, 'node_modules'), 'dir');
  fs.mkdirSync(path.join(dir, 'certs'));
  const run = args => execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' });
  run(['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
    '-keyout','certs/privkey.pem','-out','certs/fullchain.pem']);
  fs.copyFileSync(path.join(dir,'certs/fullchain.pem'),path.join(dir,'certs/root-ca.crt'));
  fs.copyFileSync(path.join(dir,'certs/fullchain.pem'),path.join(dir,'certs/intermediate-ca.crt'));
  run(['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=Factory CA',
    '-keyout','ca.key','-out','certs/idevid-ca.crt']);
  run(['req','-newkey','rsa:2048','-nodes','-subj','/CN=kms-123.factory.example',
    '-keyout','device.key','-out','device.csr']);
  run(['x509','-req','-in','device.csr','-CA','certs/idevid-ca.crt','-CAkey','ca.key',
    '-CAcreateserial','-out','device.crt','-days','1']);
  for (const prefix of ['operational', 'old']) {
    run(['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj',`/CN=${prefix} CA`,
      '-keyout',`${prefix}-ca.key`,'-out',`certs/${prefix}-ca.crt`, '-addext','basicConstraints=critical,CA:TRUE']);
    run(['req','-newkey','rsa:2048','-nodes','-subj',`/CN=${prefix}-client`,
      '-keyout',`${prefix}-client.key`,'-out',`${prefix}-client.csr`]);
    run(['x509','-req','-in',`${prefix}-client.csr`,'-CA',`certs/${prefix}-ca.crt`,
      '-CAkey',`${prefix}-ca.key`,'-CAcreateserial','-out',`${prefix}-client.crt`,'-days','1']);
  }
  fs.copyFileSync(path.join(dir,'certs/old-ca.crt'),path.join(dir,'certs/root-ca.crt'));
  const freePort = async () => {
    const s = net.createServer();
    await new Promise(resolve => s.listen(0,'127.0.0.1',resolve));
    const port = s.address().port;
    await new Promise(resolve => s.close(resolve));
    return port;
  };
  const httpPort = await freePort();
  const mqttPort = await freePort();
  const shim = path.join(dir,'listen.js');
  fs.writeFileSync(shim, `const net=require('node:net'); const old=net.Server.prototype.listen;
net.Server.prototype.listen=function(...a){if(typeof a[0]==='number'){a[0]=a[0]===3000?Number(process.env.TEST_HTTP_PORT):Number(process.env.TEST_MQTT_PORT);if(typeof a[1]==='function')a.splice(1,0,'127.0.0.1');else a[1]='127.0.0.1';}return old.apply(this,a);};\n`);
  const child = spawn(process.execPath, [path.join(dir,'mqtt.js')], {
    cwd:dir, stdio:'ignore', env:{PATH:process.env.PATH, HOME:dir, NODE_OPTIONS:`--require=${shim}`,
      TEST_HTTP_PORT:String(httpPort), TEST_MQTT_PORT:String(mqttPort), IDEVID_ISSUE_API_KEY:'test-operator',
      IDEVID_CA_ISSUER_CN:'Factory CA', IDEVID_SUBJECT_SUFFIX:'factory.example',
      MQTT_OPERATIONAL_CA_FILE:path.join(dir,'certs','operational-ca.crt')}
  });
  t.after(() => { if (child.exitCode === null) child.kill('SIGTERM'); });
  const base=`http://127.0.0.1:${httpPort}`;
  for (let n=0; n<100; n++) {
    if (child.exitCode !== null) throw new Error(`server exited ${child.exitCode}`);
    try { if ((await fetch(`${base}/version`)).ok) break; } catch (_) {}
    await new Promise(resolve => setTimeout(resolve, 100));
    if (n===99) throw new Error('server did not start');
  }
  const socket=tls.connect({host:'127.0.0.1',port:mqttPort,rejectUnauthorized:false,
    key:fs.readFileSync(path.join(dir,'device.key')),cert:fs.readFileSync(path.join(dir,'device.crt'))});
  t.after(() => socket.destroy());
  await new Promise((resolve,reject) => { socket.once('secureConnect',resolve); socket.once('error',reject); });
  const parser=mqtt.parser(); socket.on('data',chunk=>parser.parse(chunk));
  const send=packet=>socket.write(mqtt.generate(packet));
  let reportReady=true, commands=0;
  const subscribed = new Promise(resolve => parser.on('packet', packet => {
    if (packet.cmd==='connack') send({cmd:'subscribe',messageId:1,qos:1,subscriptions:[
      {topic:'commission/kms-123/readiness-request',qos:0},{topic:'commission/kms-123/command',qos:0}]});
    if (packet.cmd==='suback') resolve();
    if (packet.cmd==='publish' && packet.topic.endsWith('/readiness-request')) {
      const request=JSON.parse(packet.payload.toString());
      send({cmd:'publish',topic:'commission/kms-123/readiness-response',qos:0,
        payload:JSON.stringify({version:1,request_id:request.request_id,ready:reportReady})});
    }
    if (packet.cmd==='publish' && packet.topic.endsWith('/command')) commands++;
  }));
  send({cmd:'connect',protocolId:'MQTT',protocolVersion:4,clientId:'factory-test',clean:true,keepalive:30});
  await subscribed;
  const post=key=>fetch(`${base}/api/v1/devices/kms-123/commission-commands`,{method:'POST',
    headers:{'Content-Type':'application/json','X-Commission-Command-Key':'test-operator','Idempotency-Key':key},body:'{}'});
  reportReady=false;
  assert.equal((await post('not-ready')).status,409);
  assert.equal(commands,0);
  reportReady=true;
  assert.equal((await post('ready')).status,202);
  for (let n=0; n<20 && commands===0; n++) await new Promise(resolve=>setTimeout(resolve,25));
  assert.equal(commands,1);
  async function brokerAccepts(prefix) {
    const client=tls.connect({host:'127.0.0.1',port:mqttPort,rejectUnauthorized:false,
      key:fs.readFileSync(path.join(dir,`${prefix}-client.key`)),
      cert:fs.readFileSync(path.join(dir,`${prefix}-client.crt`))});
    return await new Promise(resolve => {
      let done=false;
      const finish=value=>{ if (!done) { done=true; clearTimeout(timer); client.destroy(); resolve(value); } };
      const timer=setTimeout(()=>finish(false),5000);
      const packets=mqtt.parser(); client.on('data', chunk=>packets.parse(chunk));
      packets.on('packet', packet=>{ if (packet.cmd==='connack') finish(packet.returnCode===0); });
      client.on('secureConnect',()=>client.write(mqtt.generate({cmd:'connect',protocolId:'MQTT',
        protocolVersion:4,clientId:`${prefix}-test`,clean:true,keepalive:30})));
      client.on('error',()=>finish(false)); client.on('close',()=>finish(false));
    });
  }
  assert.equal(await brokerAccepts('operational'), true, 'new operational client CA is trusted');
  assert.equal(await brokerAccepts('old'), false, 'old operational client CA is rejected');
  // The live combined broker accepts both identities. A separate operational
  // listener proves it can trust LDevID while rejecting a factory IDevID.
  const operationalOnly=tls.createServer({
    key:fs.readFileSync(path.join(dir,'certs/privkey.pem')),
    cert:fs.readFileSync(path.join(dir,'certs/fullchain.pem')),
    ca:fs.readFileSync(path.join(dir,'certs/operational-ca.crt')),
    requestCert:true,rejectUnauthorized:true
  }, peer=>peer.end('accepted'));
  await new Promise(resolve=>operationalOnly.listen(0,'127.0.0.1',resolve));
  t.after(()=>operationalOnly.close());
  async function operationalListenerAccepts(key,cert) {
    return await new Promise(resolve=>{
      const peer=tls.connect({host:'127.0.0.1',port:operationalOnly.address().port,rejectUnauthorized:false,
        key:fs.readFileSync(path.join(dir,key)),cert:fs.readFileSync(path.join(dir,cert))});
      let done=false;
      const finish=value=>{if(!done){done=true;clearTimeout(timer);peer.destroy();resolve(value);}};
      const timer=setTimeout(()=>finish(false),5000);
      peer.on('data',data=>finish(data.toString()==='accepted'));
      peer.on('error',()=>finish(false)); peer.on('close',()=>finish(false));
    });
  }
  assert.equal(await operationalListenerAccepts('operational-client.key','operational-client.crt'),true);
  assert.equal(await operationalListenerAccepts('device.key','device.crt'),false);
});
