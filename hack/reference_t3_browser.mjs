// Real browser, fixed product images, synthetic private credentials. Never emit protocol payloads.
// ref: microsoft/playwright v1.60.0 packages/playwright-core/src/server/browserContext.ts
import fs from 'node:fs';
import crypto from 'node:crypto';
import { chromium } from '/opt/playwright-core/index.mjs';
const input=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const state=fs.existsSync(input.privateFile)?JSON.parse(fs.readFileSync(input.privateFile,'utf8')):{contexts:{},data:{},secrets:[]};
const origin=input.origin, tenant=input.tenants[0], other=input.tenants[1];
const data=state.data;
let browser, assertions=0, diagnostic='start';
const active=[];
function check(ok,code){diagnostic=code;assertions++;if(!ok)throw Error(code);}
function remember(value){if(value)state.secrets.push(value);return value;}
function save(){fs.writeFileSync(input.privateFile,JSON.stringify(state),{mode:0o600});fs.chmodSync(input.privateFile,0o600);}
async function open(role,t=tenant,fresh=false){
 diagnostic='open-'+role;
 const context=await browser.newContext({baseURL:origin,storageState:fresh?undefined:state.contexts[role],locale:'en-US'});
 const page=await context.newPage();page.setDefaultTimeout(20000);page.setDefaultNavigationTimeout(30000);
 const value={role,t,context,page};active.push(value);await page.goto(`${origin}/tenants/${t}/login`);return value;
}
async function store(c){state.contexts[c.role]=await c.context.storageState();for(const cookie of state.contexts[c.role].cookies)remember(cookie.value);save();}
async function read(c,path){
 const response=await c.context.request.get(origin+path);let body=null;try{body=await response.json();}catch{}
 return {status:response.status(),body,headers:response.headers()};
}
async function current(c){return read(c,`/api/v2/tenants/${c.t}/session`);}
async function request(c,method,path,body,headers={}){
 return c.page.evaluate(async ({method,url,body,headers})=>{
  const r=await fetch(url,{method,credentials:'include',headers:{'content-type':'application/json','x-identity-request':'1',...headers},...(body===undefined?{}:{body:JSON.stringify(body)})});
  let value=null;try{value=await r.json();}catch{}
  return {status:r.status,body:value};
 },{method,url:origin+path,body,headers});
}
async function write(c,method,suffix,body){
 const session=await current(c);check(session.status===200,'writer-session');remember(session.body.csrfToken);
 return request(c,method,`/api/v2/tenants/${c.t}/${suffix}`,body,{'x-csrf-token':session.body.csrfToken});
}
async function sessions(c){await c.page.goto(`${origin}/tenants/${c.t}/sessions`);await c.page.locator('h1').waitFor();}
async function login(c,name,password){
 diagnostic='local-login-form';
 await c.page.goto(`${origin}/tenants/${c.t}/login`);
 await c.page.locator('#login-name').fill(name);await c.page.locator('#login-password').fill(password);
 const response=c.page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname===`/api/v2/tenants/${c.t}/login`);
 await c.page.locator('#login-password').locator('xpath=ancestor::form').locator('button[type=submit]').click();
 check((await response).status()===200,'ui-local-login');await c.page.waitForURL(`**/tenants/${c.t}/sessions`);
 await store(c);return current(c);
}
async function admin(t=tenant){
 const c=await open(t===tenant?'admin':'other-admin',t);
 if((await current(c)).status!==200)await login(c,'operator',t===tenant?(data.recoveredAdminPassword??input.adminPassword):input.adminPassword);
 await sessions(c);
 const session=await current(c);
 if(Date.now()/1000-session.body.session.authTime>=270){
  await c.page.locator('#reauth-password').fill(t===tenant?(data.recoveredAdminPassword??input.adminPassword):input.adminPassword);
  const response=c.page.waitForResponse(r=>r.url().endsWith('/session/reauthenticate')&&r.request().method()==='POST');
  await c.page.locator('#reauth-password').locator('xpath=ancestor::form').locator('button').click();
  check((await response).status()===200,'admin-reauthentication');await c.page.reload();await store(c);
 }
 return c;
}
async function createAccount(c,name,password,expected=201){
 await c.page.goto(`${origin}/tenants/${c.t}/accounts`);await c.page.locator('#account-login').fill(name);await c.page.locator('#account-password').fill(password);
 const response=c.page.waitForResponse(r=>r.url().endsWith('/accounts')&&r.request().method()==='POST');
 await c.page.locator('#account-password').locator('xpath=ancestor::form').locator('button[type=submit]').click();
 const r=await response;check(r.status()===expected,'ui-create-account');
 if(expected===201){const value=await r.json();data.accounts??={};data.accounts[name]=value.principalId;await c.page.getByText(name,{exact:true}).first().waitFor();return value;}
 await c.page.getByRole('alert').waitFor();
}
async function provider(c){
 const r=await read(c,`/api/v2/tenants/${c.t}/providers`);check(r.status===200&&r.body.providers.length===1,'provider-list');return r.body.providers[0];
}
async function createProvider(c){
 await c.page.goto(`${origin}/tenants/${c.t}/providers`);await c.page.locator('#issuer').fill(input.issuer);await c.page.locator('#client-id').fill('reference');await c.page.locator('#client-secret').fill(input.clientSecret);await c.page.locator('#ca-pem').fill(input.idpCa);await c.page.locator('#scopes').fill('openid');await c.page.locator('#email-claim').fill('');await c.page.locator('#groups-claim').fill('');await c.page.locator('#jit').check();
 const response=c.page.waitForResponse(r=>r.url().endsWith('/providers')&&r.request().method()==='POST');await c.page.locator('#issuer').locator('xpath=ancestor::form').locator('button[type=submit]').click();
 const r=await response;check(r.status()===201,'ui-provider-create');const p=await r.json();
 const enabled=await write(c,'POST',`providers/${p.id}/enabled`,{expectedVersion:p.version,enabled:true});check(enabled.status===200,'provider-enable');
 data.providers??={};data.providers[c.t]=p.id;await store(c);
}
async function expectOldCookie(c,cookies,t=tenant){
 const temp=await browser.newContext({baseURL:origin,storageState:{cookies,origins:[]}});
 const r=await temp.request.get(`${origin}/api/identity-host/v1/tenants/${t}/context`);check(r.status()===401,'old-cookie-rejected');await temp.close();
}
function totp(){
 const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));
 const mac=crypto.createHmac('sha1',input.otpSecret).update(counter).digest();const offset=mac[19]&15;
 return remember(String((mac.readUInt32BE(offset)&0x7fffffff)%1000000).padStart(6,'0'));
}
async function keycloak(c,user,{otp=false,badPassword=false,badOtp=false,success=true}={}){
 await c.page.locator('#username').waitFor();await c.page.locator('#username').fill(user);await c.page.locator('#password').fill(badPassword?'wrong-private-password':input.idpPassword);await c.page.locator('#kc-login').click();
 if(badPassword){await c.page.locator('#password').waitFor();check(!(await c.context.cookies(origin)).some(x=>x.name==='__Host-identity-session'),'wrong-idp-password-no-session');await c.page.locator('#password').fill(input.idpPassword);await c.page.locator('#kc-login').click();}
 if(otp){
  await c.page.locator('#otp').waitFor();
  if(badOtp){const wrong=String((Number(totp())+123456)%1000000).padStart(6,'0');await c.page.locator('#otp').fill(wrong);await c.page.locator('#kc-login').click();await c.page.locator('#otp').waitFor();}
  await c.page.locator('#otp').fill(totp());await c.page.locator('#kc-login').click();
 }
 await c.page.waitForURL(u=>u.origin===origin);
 if(success){await c.page.waitForURL(`**/tenants/${c.t}/sessions`);check((await current(c)).status===200,'oidc-session');}
 else check((await read(c,`/api/identity-host/v1/tenants/${c.t}/mfa-example`)).status!==200,'failed-mfa-not-authorized');
 await store(c);
}
async function sso(role,user,t=tenant,options={}){
 const c=await open(role,t,true);await c.page.getByRole('button',{name:/Organization SSO|组织 SSO/}).click();await keycloak(c,user,options);return c;
}
async function stepUp(c,user='bob',options={}){
 await sessions(c);await c.page.getByRole('button',{name:/Step up authentication|增强认证/}).click();await keycloak(c,user,{otp:true,...options});
}
async function local(){
 const a=await admin();const b=await admin(other);
 const cookies=await a.context.cookies(origin);const cookie=cookies.find(x=>x.name==='__Host-identity-session');check(cookie&&cookie.secure&&cookie.httpOnly&&cookie.sameSite==='Lax'&&cookie.path==='/'&&cookie.domain==='identity.example.test','browser-cookie-attributes');
 check((await read(a,`/api/identity-host/v1/tenants/${other}/context`)).status===401,'tenant-isolation');
 const anon=await open('anonymous',tenant,true);check((await read(anon,`/api/identity-host/v1/tenants/${tenant}/context`)).status===401,'anonymous-resource');
 for(const name of ['local','linked','disabled','inactive','limited'])await createAccount(a,name,input.userPassword);
 const c=await open('local',tenant,true);await login(c,'local',input.userPassword);
 check((await read(c,`/api/v2/tenants/${tenant}/accounts`)).status===403,'nonmanager-server-denial');
 const before=await current(c);const old=await c.context.cookies();
 const bad=await c.context.request.post(`${origin}/api/v2/tenants/${tenant}/session/refresh`,{headers:{origin,'x-identity-request':'1','x-csrf-token':'0'.repeat(64)}});check(bad.status()===403,'csrf-rejection');
 const evil=await c.context.request.post(`${origin}/api/v2/tenants/${tenant}/session/refresh`,{headers:{origin:'https://untrusted.example.test','x-identity-request':'1','x-csrf-token':before.body.csrfToken}});check(evil.status()===403,'origin-rejection');
 const refreshed=await write(c,'POST','session/refresh',{});check(refreshed.status===200&&refreshed.body.session.authTime===before.body.session.authTime&&refreshed.body.session.absoluteExpiresAt===before.body.session.absoluteExpiresAt,'refresh-lifetimes');await expectOldCookie(c,old);
 await sessions(c);await c.page.locator('#current-password').fill(input.userPassword);await c.page.locator('#new-password').fill(input.nextPassword);
 const changed=c.page.waitForResponse(r=>r.url().endsWith('/account/password')&&r.request().method()==='POST');await c.page.locator('#new-password').locator('xpath=ancestor::form').locator('button[type=submit]').click();check((await changed).status()===200,'ui-change-password');await c.page.waitForURL(`**/tenants/${tenant}/login`);
 await login(c,'local',input.nextPassword);const currentCookie=await c.context.cookies();
 await c.page.getByRole('button',{name:/^Sign out$|^退出当前会话$/}).click();await c.page.waitForURL(`**/tenants/${tenant}/login`);await expectOldCookie(c,currentCookie);
 await login(c,'local',input.nextPassword);const allCookie=await c.context.cookies();await c.page.getByRole('button',{name:/Sign out all sessions|退出全部会话/}).click();await c.page.waitForURL(`**/tenants/${tenant}/login`);await expectOldCookie(c,allCookie);
 const limited=await open('limited',tenant,true);let failures=0;
 for(let i=0;i<6;i++){const r=await request(limited,'POST',`/api/v2/tenants/${tenant}/login`,{login:'limited',password:'wrong-private-password'});check(r.status===(i<5?401:429),'failed-attempt-budget');failures++;}
 const blocked=await request(limited,'POST',`/api/v2/tenants/${tenant}/login`,{login:'limited',password:input.userPassword});check(blocked.status===429,'correct-password-obeys-budget');
 await store(a);await store(b);return {cookieAttributes:true,tenantAndPrivilegeDenied:true,failedAttempts:failures,sessionRotationAndRevocation:true};
}
async function oidc(){
 const a=await admin();const b=await admin(other);await createProvider(a);await createProvider(b);
 const alice=await sso('alice','alice',tenant,{badPassword:true});const one=await current(alice);data.alicePrincipal=one.body.identity.principalId;
 const aliceOther=await sso('alice-other','alice',other);check((await current(aliceOther)).body.identity.principalId!==data.alicePrincipal,'jit-tenant-identity-isolation');
 const linked=await open('linked',tenant,true);await login(linked,'linked',input.userPassword);await linked.page.locator('#link-provider').selectOption(data.providers[tenant]);await linked.page.locator('#link-password').fill(input.userPassword);await linked.page.locator('#link-password').locator('xpath=ancestor::form').locator('button').click();await keycloak(linked,'bob');
 check((await current(linked)).body.identity.principalId===data.accounts.linked,'explicit-link-subject');check(data.accounts.linked!==data.alicePrincipal,'no-email-auto-link');
 const weak=await read(linked,`/api/identity-host/v1/tenants/${tenant}/mfa-example`);check(weak.status===403,'ordinary-login-is-not-mfa');await store(linked);
 // Capture a real callback and deliver it without the originating browser cookie first.
 const bound=await open('bound',tenant,true);let callback;
 await bound.page.route(`${origin}/api/v2/oidc/callback**`,async route=>{callback=route.request().url();for(const [,v] of new URL(callback).searchParams)remember(v);await route.abort();});
 await bound.page.getByRole('button',{name:/Organization SSO|组织 SSO/}).click();
 await bound.page.locator('#username').fill('alice');await bound.page.locator('#password').fill(input.idpPassword);await bound.page.locator('#kc-login').click();
 for(let i=0;!callback&&i<100;i++)await new Promise(r=>setTimeout(r,50));check(Boolean(callback),'captured-callback');
 const foreign=await browser.newContext();const rejected=await foreign.request.get(callback);check(rejected.status()>=400,'callback-browser-binding');await foreign.close();
 await bound.page.unroute(`${origin}/api/v2/oidc/callback**`);await bound.page.goto(callback);await bound.page.waitForURL(`**/tenants/${tenant}/sessions`);check((await current(bound)).status===200,'bound-callback-completes');
 const replay=await bound.context.request.get(callback);check(replay.status()>=400,'callback-replay-rejected');await store(bound);
 return {jitAndExplicitLink:true,tenantIdentityIsolated:true,wrongPasswordRejected:true,browserBindingAndReplay:true};
}
async function mfa(){
 const c=await open('linked');await sessions(c);const before=await c.context.cookies();
 await stepUp(c,'alice',{success:false});check((await current(c)).body.identity.principalId===data.accounts.linked,'wrong-subject-did-not-rebind');
 let downgraded=false;await c.page.route(input.issuer.split('/realms')[0]+'/**',async route=>{const u=new URL(route.request().url());if(!downgraded&&u.searchParams.get('acr_values')==='2'){u.searchParams.set('acr_values','1');downgraded=true;await route.continue({url:u.toString()});}else await route.continue();});
 await sessions(c);await c.page.getByRole('button',{name:/Step up authentication|增强认证/}).click();await keycloak(c,'bob',{success:false});await c.page.unroute(input.issuer.split('/realms')[0]+'/**');check(downgraded,'browser-assurance-downgrade-exercised');
 await stepUp(c,'bob',{badOtp:true});await expectOldCookie(c,before);
 let resource=await read(c,`/api/identity-host/v1/tenants/${tenant}/mfa-example`);check(resource.status===200&&resource.body.authentication.acr==='mfa','fresh-mfa-resource');check(resource.body.principalId===data.accounts.linked,'mfa-subject');
 const authTime=resource.body.authentication.authTime;const refresh=await write(c,'POST','session/refresh',{});check(refresh.status===200,'mfa-refresh');
 resource=await read(c,`/api/identity-host/v1/tenants/${tenant}/mfa-example`);check(resource.body.authentication.authTime===authTime,'refresh-does-not-refresh-mfa');
 await new Promise(r=>setTimeout(r,Math.max(0,(authTime+301)*1000-Date.now())));
 check((await read(c,`/api/identity-host/v1/tenants/${tenant}/mfa-example`)).status===403,'mfa-real-expiry');
 await stepUp(c);check((await read(c,`/api/identity-host/v1/tenants/${tenant}/mfa-example`)).status===200,'repeat-step-up');
 const a=await admin();const p=await provider(a);const disabled=await write(a,'POST',`providers/${p.id}/enabled`,{expectedVersion:p.version,enabled:false});check(disabled.status===200,'provider-disabled');
 check((await current(c)).status===401,'provider-disable-revokes-session');
 const enabled=await write(a,'POST',`providers/${p.id}/enabled`,{expectedVersion:disabled.body.version,enabled:true});check(enabled.status===200,'provider-reenabled');check((await current(c)).status===401,'provider-enable-does-not-revive-session');
 await login(c,'linked',input.userPassword);await stepUp(c);await store(c);await store(a);
 return {freshMfaConsumed:true,realExpiryRejected:true,oldSessionRejected:true,wrongSubjectAndDowngradeRejected:true,wrongTotpRejected:true};
}
async function responseLoss(){
 const a=await admin();await a.page.goto(`${origin}/tenants/${tenant}/accounts`);let requests=0;
 await a.page.route(`${origin}/api/v2/tenants/${tenant}/accounts`,async route=>{
  if(route.request().method()!=='POST'){await route.continue();return;}
  requests++;const reply=await route.fetch();check(reply.status()===201,'lost-response-actually-committed');await route.abort('connectionreset');
 });
 await a.page.locator('#account-login').fill('uncertain');await a.page.locator('#account-password').fill(input.userPassword);await a.page.locator('#account-password').locator('xpath=ancestor::form').locator('button[type=submit]').click();await a.page.getByRole('alert').waitFor();await new Promise(r=>setTimeout(r,300));check(requests===1,'unknown-write-not-retried');await a.page.unroute(`${origin}/api/v2/tenants/${tenant}/accounts`);await store(a);return {singleWrite:true,noFalseUiSuccess:true};
}
async function providerReady(){
 const a=await admin();let okay=false;
 for(let i=0;i<30;i++){const p=await provider(a);const r=await write(a,'POST',`providers/${p.id}/test`,{});if(r.status===200&&r.body.passed===true){okay=true;break;}await new Promise(r=>setTimeout(r,1000));}
 check(okay,'provider-ready');await store(a);return {providerReachable:true};
}
async function beginState(){const c=await open('pending-state',tenant,true);const r=await request(c,'POST',`/api/v2/tenants/${tenant}/oidc/${data.providers[tenant]}/login`,{returnTarget:'resume'});check(r.status===200,'begin-state');data.pendingState=r.body.authorizationUrl;for(const [,v] of new URL(data.pendingState).searchParams)remember(v);await store(c);return {started:true};}
async function recoveryState(){
 const a=await admin();
 for(const [name,field] of [['disabled','enabled'],['inactive','membership']]){const r=await write(a,'POST',`accounts/${data.accounts[name]}/${field}`,{enabled:false});check(r.status===200,'recovery-negative-account-state');}
 data.preRecoveryAdminCookies=await a.context.cookies();await store(a);return {disabledAndInactivePresent:true};
}
async function capacity(){
 const a=await admin();const times=[],sessionTimes=[];let unexpected=0,limited=0,success=0;
 for(let i=0;i<5;i++){
  const created=await write(a,'POST','accounts',{login:'capacity-'+i,password:input.userPassword});check(created.status===201,'capacity-account');
  const c=await open('capacity-'+i,tenant,true);const begin=performance.now();const result=await request(c,'POST',`/api/v2/tenants/${tenant}/login`,{login:'capacity-'+i,password:input.userPassword});
  if(result.status===200){times.push(performance.now()-begin);success++;}else if(result.status===429)limited++;else unexpected++;
 }
 check(times.length>0,'login-baseline-samples');
 const started=performance.now();
 for(const concurrency of [1,4,16]){
  const until=performance.now()+30000;
  while(performance.now()<until)await Promise.all(Array.from({length:concurrency},async()=>{const start=performance.now();const r=await read(a,`/api/identity-host/v1/tenants/${tenant}/context`);if(r.status!==200)unexpected++;sessionTimes.push(performance.now()-start);}));
 }
 const elapsed=(performance.now()-started)/1000;
 const p95=values=>[...values].sort((a,b)=>a-b)[Math.min(values.length-1,Math.ceil(values.length*.95)-1)];
 check(unexpected===0,'capacity-unexpected-errors');await store(a);
 return {measurements:{loginP95Ms:p95(times),sessionP95Ms:p95(sessionTimes),sessionRequestsPerSecond:sessionTimes.length/elapsed,unexpectedErrors:unexpected},counts:{loginSamples:success,limitedLogins:limited,sessionSamples:sessionTimes.length}};
}
let observations;
try{
 diagnostic='browser-launch';browser=await chromium.launch({headless:true});
 switch(input.phase){
 case 'local':observations=await local();break;
 case 'oidc':observations=await oidc();break;
 case 'mfa':observations=await mfa();break;
 case 'rollback':{const a=await admin();await createAccount(a,'rolled-back',input.userPassword,503);await store(a);observations={uiRejected:true};break;}
 case 'response-loss':observations=await responseLoss();break;
 case 'idp-down':{const local=await open('emergency-local',other,true);await login(local,'operator',input.adminPassword);const a=await admin();const p=await provider(a);const result=await write(a,'POST',`providers/${p.id}/test`,{});check(result.status===200&&result.body.passed===false,'idp-unavailable');observations={localLogin:true,upstreamFailure:true};break;}
 case 'provider-ready':observations=await providerReady();break;
 case 'pg-down':{const a=await open('admin');check((await read(a,`/api/identity-host/v1/tenants/${tenant}/context`)).status===503,'pg-resource-denied');const anon=await open('pg-login',other,true);const r=await request(anon,'POST',`/api/v2/tenants/${other}/login`,{login:'operator',password:input.adminPassword});check(r.status===503,'pg-login-denied');observations={authorityUnavailable:true};break;}
 case 'pg-ready':{const a=await admin();check((await read(a,`/api/identity-host/v1/tenants/${tenant}/context`)).status===200,'storage-recovered');await store(a);observations={storageRecovered:true};break;}
 case 'begin-old-state':observations=await beginState();break;
 case 'reject-old-state':{const c=await open('pending-state');await c.page.goto(data.pendingState);await keycloak(c,'alice',{success:false});check((await current(c)).status===401,'old-state-no-session');observations={oldStateRejected:true};break;}
 case 'fresh-sso':{const c=await sso('fresh-sso','alice');await store(c);observations={freshSso:true};break;}
 case 'old-client-secret':{const c=await sso('old-secret','alice',tenant,{success:false});check((await current(c)).status===401,'old-secret-no-session');observations={oldSecretRejected:true};break;}
 case 'update-client-secret':{const a=await admin();const p=await provider(a);const r=await write(a,'PUT',`providers/${p.id}`,{expectedVersion:p.version,settings:p.settings,clientSecret:input.clientSecret,caPem:input.idpCa});check(r.status===200,'client-secret-updated');await store(a);observations={updated:true};break;}
 case 'recovery-state':observations=await recoveryState();break;
 case 'restored':{const c=await open('restored-admin',tenant,true);await expectOldCookie(c,data.preRecoveryAdminCookies);const old=await request(c,'POST',`/api/v2/tenants/${tenant}/login`,{login:'operator',password:input.adminPassword});check(old.status===401,'restored-old-password');data.recoveredAdminPassword=input.recoveredAdminPassword;const a=await admin();check((await current(a)).status===200,'restored-new-password');for(const name of ['disabled','inactive']){const r=await request(c,'POST',`/api/v2/tenants/${tenant}/login`,{login:name,password:input.userPassword});check(r.status===401,'restored-disabled-member');}await sso('restored-sso','alice');await store(a);observations={oldCredentialsRejected:true,localAndOidcRecovered:true};break;}
 case 'capacity':observations=await capacity();break;
 default:throw Error('unknown-scenario');
 }
 for(const c of active)await store(c);
 observations.assertions=assertions;
 console.log(JSON.stringify({status:'passed',observations}));
}catch(failure){
 const network=String(failure?.message??'').match(/net::([A-Z_]+)/);
 if(network)diagnostic+='-'+network[1].toLowerCase().replaceAll('_','-');
 else if(failure?.name==='TimeoutError')diagnostic+='-timeout';
 save();fs.writeFileSync(input.privateFile+'.failure',JSON.stringify({phase:input.phase,diagnostic}),{mode:0o600});
 console.log(JSON.stringify({status:'failed',phase:input.phase,diagnostic}));process.exitCode=1;
}finally{if(browser)await browser.close();}
