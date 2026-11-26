const CORS={"x-content-type-options":"nosniff","referrer-policy":"strict-origin-when-cross-origin","x-frame-options":"DENY"};
const json=(data,status=200,extra={})=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json","cache-control":"no-store",...CORS,...extra}});
const enc=new TextEncoder();
const roles=new Set(["producer","importer","brand-owner"]);
const labels={producer:"Producer",importer:"Importer", "brand-owner":"Brand Owner"};
const PBKDF2_ITERATIONS=10000; // Temporary Workers Free testing baseline; raise on a paid CPU budget before production.
const LEGACY_PBKDF2_ITERATIONS=600000;
function hex(bytes){return [...new Uint8Array(bytes)].map(x=>x.toString(16).padStart(2,"0")).join("")}
function bytesFromHex(h){return Uint8Array.from(h.match(/../g).map(x=>parseInt(x,16)))}
async function derivePassword(password,salt,iterations){
  const key=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations,hash:"SHA-256"},key,256);
  return hex(bits);
}
async function hashPassword(password){
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const digest=await derivePassword(password,salt,PBKDF2_ITERATIONS);
  return `v2$${PBKDF2_ITERATIONS}$${hex(salt)}$${digest}`;
}
async function verifyPassword(password,stored){
  if(!stored)return false;
  let iterations=PBKDF2_ITERATIONS,saltHex,digest;
  const parts=stored.split("$");
  if(parts.length===4 && parts[0]==="v2"){iterations=Number(parts[1]);saltHex=parts[2];digest=parts[3];}
  else if(stored.includes(":")){[saltHex,digest]=stored.split(":");iterations=LEGACY_PBKDF2_ITERATIONS;}
  else return false;
  if(!Number.isInteger(iterations)||iterations<1000||iterations>600000||!saltHex||!digest)return false;
  const actual=await derivePassword(password,bytesFromHex(saltHex),iterations);
  if(actual.length!==digest.length)return false;let diff=0;for(let i=0;i<actual.length;i++)diff|=actual.charCodeAt(i)^digest.charCodeAt(i);return diff===0;
}
async function tableInfo(env,table){
  const allowed=new Set(["users","sessions","companies","compliance_profiles"]);
  if(!allowed.has(table))throw new Error("Invalid table");
  const rows=await env.DB.prepare(`PRAGMA table_info(${table})`).all();
  return rows.results||[];
}
async function columnType(env,table,column){
  const rows=await tableInfo(env,table);
  const c=rows.find(x=>x.name===column);
  if(!c)throw new Error(`${table}.${column} column not found`);
  return String(c.type||"").toUpperCase();
}
async function getSessionColumn(env){
  const rows=await tableInfo(env,"sessions");
  const names=rows.map(x=>x.name);
  if(names.includes("token"))return "token";
  if(names.includes("id"))return "id";
  throw new Error("Sessions table must contain id or token");
}
function isIntegerType(type){return /INT/i.test(type)}
function token(){const bytes=new Uint8Array(32);crypto.getRandomValues(bytes);return hex(bytes)}
function sessionCookie(value,maxAge=2592000){return `__Host-eprtrack_session=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`}
function clearSessionCookie(){return "__Host-eprtrack_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"}
function cookieValue(request,name="__Host-eprtrack_session"){const raw=request.headers.get("cookie")||"";for(const part of raw.split(";")){const [k,...v]=part.trim().split("=");if(k===name)return v.join("=")}return null}
function sameOrigin(request){const origin=request.headers.get("origin");return !origin||origin===new URL(request.url).origin}
async function auth(request,env){
  const sid=cookieValue(request); if(!sid)return null;
  const col=await getSessionColumn(env);
  return (await env.DB.prepare(`SELECT u.id,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.${col}=? AND s.expires_at>datetime('now')`).bind(sid).first())||null;
}
async function rules(env,request){const r=await env.ASSETS.fetch(new URL("/rules.json",request.url));if(!r.ok)throw new Error("Rules unavailable");return r.json()}
async function ownership(env,userId,companyId){return await env.DB.prepare("SELECT * FROM companies WHERE id=? AND user_id=?").bind(companyId,userId).first()}
async function ensureWorkspaceTasks(env){
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS workspace_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    due_date TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    priority TEXT NOT NULL DEFAULT 'normal',
    source_url TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT
  )`).run();
}
function fyEndYear(fy){const m=String(fy||'').match(/(\d{4})-(\d{2,4})/);return m?Number(m[1])+1:null}
async function seedWorkspaceTasks(env,company){
  await ensureWorkspaceTasks(env);
  const row=await env.DB.prepare("SELECT COUNT(*) AS n FROM workspace_tasks WHERE company_id=?").bind(company.id).first();
  if(Number(row?.n||0)>0)return;
  const end=fyEndYear(company.fy);
  const annualDue=null; // Verify the applicable official deadline before entering it.
  const source='https://eprplastic.cpcb.gov.in/plastic/downloads/4th%20Amendment%20%28EPR%20guidelines%29%20Feb%202022.pdf';
  const tasks=[
    ['Verify your official EPR target','Enter the applicable target shown in your official CPCB records. EPRTrack does not determine the legal target in this version.',null,'high',null],
    ['Record achieved / credited quantity','Update the quantity you have evidence for as compliance activity progresses.',null,'normal',null],
    ['Prepare annual return','Keep supporting records ready and verify your applicable filing deadline on the official portal.',annualDue,'high',source],
    ['Review CPCB updates','Check the Common EPR Portal and CPCB notices for extensions, changes or new instructions.',null,'normal','https://epr.cpcb.gov.in/']
  ];
  for(const [title,description,due,priority,url] of tasks){
    await env.DB.prepare("INSERT INTO workspace_tasks(company_id,title,description,due_date,status,priority,source_url) VALUES(?,?,?,?,?,?,?)").bind(company.id,title,description,due,'open',priority,url).run();
  }
}
async function readBody(request){const raw=await request.text();if(raw.length>65536)throw Object.assign(new Error("Request body too large"),{status:413});let value;try{value=JSON.parse(raw)}catch{throw Object.assign(new Error("Invalid JSON"),{status:400})}if(!value||typeof value!=="object"||Array.isArray(value))throw Object.assign(new Error("Expected a JSON object"),{status:400});return value}
async function authThrottle(env,request,email,mode){const ip=request.headers.get("CF-Connecting-IP")||"local";const bucket=Math.floor(Date.now()/900000);await env.DB.prepare("CREATE TABLE IF NOT EXISTS auth_rate_windows (key TEXT PRIMARY KEY, bucket INTEGER NOT NULL, attempts INTEGER NOT NULL)").run();const keys=[["ip:"+ip,mode==="register"?20:40],["email:"+email,10]];for(const [key,limit] of keys){const digest=hex(await crypto.subtle.digest("SHA-256",enc.encode(mode+":"+key)));const row=await env.DB.prepare("INSERT INTO auth_rate_windows(key,bucket,attempts) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN bucket=excluded.bucket THEN attempts+1 ELSE 1 END,bucket=excluded.bucket RETURNING attempts").bind(digest,bucket).first();if(Number(row.attempts)>limit)return false}if(Math.random()<.02)await env.DB.prepare("DELETE FROM auth_rate_windows WHERE bucket<?").bind(bucket-96).run();return true}
function redirect(url){return new Response(null,{status:302,headers:{location:url}})}
export default {async fetch(request,env){
  if(request.method==="OPTIONS")return new Response("",{headers:CORS});
  const u=new URL(request.url);
  if (!sameOrigin(request) && request.method!=="GET") return json({error:"Cross-site request blocked"},403);
  try{
    if(u.pathname==="/api/health"){await env.DB.prepare("SELECT 1 FROM launch_health LIMIT 1").all();return json({ok:true,service:"eprtrack",version:"qa-2026-11-26"},200,{"cache-control":"no-store"});}

    // Server-side CTA router: logged-in users go to dashboard; others go to account creation.
    if((u.pathname==="/save-track"||u.pathname==="/save-track/")&&request.method==="GET"){
      const user=await auth(request,env);
      return redirect(user?"/dashboard/":"/auth/?mode=register&next=/dashboard/");
    }

    if(u.pathname==="/api/calculator"&&request.method==="POST"){
      const b=await readBody(request),role=String(b.role||"").toLowerCase(),cat=String(b.category||"").toUpperCase(),tonnes=Number(b.tonnes);
      if(b.tonnes==null||typeof b.tonnes==="boolean"||String(b.tonnes).trim()===""||!roles.has(role)||!["I","II","III","IV"].includes(cat)||!Number.isFinite(tonnes)||tonnes<0)return json({error:"Enter a valid role, category and quantity."},400);
      const r=await rules(env,request),rate=r.recycled_content_rate[cat];
      return json({fy:"2026-27",role,role_label:labels[role],category:cat,input_tonnes:tonnes,recycled_content_rate:rate,indicative_recycled_content_tonnes:rate==null?null:tonnes*rate,minimum_recycling_rate_of_applicable_target:r.minimum_recycling_of_applicable_target[cat],rule_version:r.version,source:r.source,verified_on:r.verified_on,notes:r.notes[role],category_note:r.category_notes[cat]||""});
    }

    if(u.pathname==="/api/auth/register"&&request.method==="POST"){
      const b=await readBody(request),email=String(b.email||"").trim().toLowerCase(),pw=String(b.password||"");
      if(!/^\S+@\S+\.\S+$/.test(email)||email.length>254||pw.length<12||pw.length>128)return json({error:"Enter a valid email and a password of 12–128 characters."},400);
      if(!(await authThrottle(env,request,email,"register")))return json({error:"Too many attempts. Try again in 15 minutes."},429,{"retry-after":"900"});
      const existing=await env.DB.prepare("SELECT id FROM users WHERE email=? LIMIT 1").bind(email).first();
      if(existing)return json({error:"An account with this email already exists. Sign in instead."},409);
      const passwordHash=await hashPassword(pw);
      const userIdType=await columnType(env,"users","id");
      let userId;
      if(isIntegerType(userIdType)){
        const inserted=await env.DB.prepare("INSERT INTO users(email,password_hash) VALUES(?,?)").bind(email,passwordHash).run();
        userId=inserted.meta?.last_row_id;
        if(userId==null)throw new Error("User insert did not return an integer row id");
      }else{
        userId=crypto.randomUUID();
        await env.DB.prepare("INSERT INTO users(id,email,password_hash) VALUES(?,?,?)").bind(userId,email,passwordHash).run();
      }
      let t;
      try{
        t=token();
        const sessionCol=await getSessionColumn(env);
        await env.DB.prepare(`INSERT INTO sessions(${sessionCol},user_id,expires_at) VALUES(?,?,datetime('now','+30 day'))`).bind(t,userId).run();
      }catch(e){
        try{await env.DB.prepare("DELETE FROM users WHERE id=?").bind(userId).run()}catch(_){}
        throw e;
      }
      return json({ok:true,user:{id:userId,email}},201,{"set-cookie":sessionCookie(t)});
    }

    if(u.pathname==="/api/auth/login"&&request.method==="POST"){
      const b=await readBody(request),email=String(b.email||"").trim().toLowerCase(),pw=String(b.password||"");
      if(email.length>254||pw.length>128||!email||!pw)return json({error:"Invalid email or password."},401);
      if(!(await authThrottle(env,request,email,"login")))return json({error:"Too many attempts. Try again in 15 minutes."},429,{"retry-after":"900"});
      const usr=await env.DB.prepare("SELECT id,email,password_hash FROM users WHERE email=? LIMIT 1").bind(email).first();
      if(!usr||!(await verifyPassword(pw,usr.password_hash)))return json({error:"Invalid email or password."},401);
      const t=token();const sessionCol=await getSessionColumn(env);await env.DB.prepare(`INSERT INTO sessions(${sessionCol},user_id,expires_at) VALUES(?,?,datetime('now','+30 day'))`).bind(t,usr.id).run();
      return json({ok:true,user:{id:usr.id,email:usr.email}},200,{"set-cookie":sessionCookie(t)});
    }

    const user=await auth(request,env);
    if(user && request.method!=="GET" && !sameOrigin(request))return json({error:"Cross-site request blocked"},403);
    if(u.pathname==="/api/auth/logout"&&request.method==="POST"){
      const sid=cookieValue(request);if(sid){const sessionCol=await getSessionColumn(env);await env.DB.prepare(`DELETE FROM sessions WHERE ${sessionCol}=?`).bind(sid).run();}
      return json({ok:true},200,{"set-cookie":clearSessionCookie()});
    }
    if(!user)return json({error:"Authentication required"},401);
    if(u.pathname==="/api/launch-records"){
      const body=request.method==="GET"?null:await readBody(request);
      const cid=request.method==="GET"?u.searchParams.get("company_id"):body.company_id;
      const company=await ownership(env,user.id,cid);
      if(!company)return json({error:"Company not found"},404);
      const key=String(company.id), fy=String(company.fy);
      if(request.method==="GET"){
        const h=await env.DB.prepare("SELECT summary FROM launch_health WHERE company_id=? AND fy=?").bind(key,fy).first();
        const e=await env.DB.prepare("SELECT id,ref,qty,party,status,note FROM launch_evidence WHERE company_id=? AND fy=? ORDER BY id DESC").bind(key,fy).all();
        return json({health:h?JSON.parse(h.summary):null,evidence:e.results||[]},200,{"cache-control":"no-store"});
      }
      if(request.method==="PUT"){
        const h=body.health||{};if(h.fy!==fy||h.category!==company.category)return json({error:'Analysis must match the selected company financial year and category.'},400);const out={file:String(h.file||'').slice(0,250),fy,category:company.category,checkedAt:new Date().toISOString()};
        for(const k of ["records","valid","review","duplicates","missingPackaging","categoryIssues","packagingTonnes"]){const n=h[k];if(typeof n!=="number"||!Number.isFinite(n)||n<0||n>1e12||(k!=="packagingTonnes"&&!Number.isInteger(n)))return json({error:"Invalid summary"},400);out[k]=n;}
        if(out.valid===0||out.valid+out.review!==out.records||['duplicates','missingPackaging','categoryIssues'].some(k=>out[k]>out.review))return json({error:"Invalid record totals"},400);
        await env.DB.prepare("INSERT INTO launch_health(company_id,fy,summary) VALUES(?,?,?) ON CONFLICT(company_id,fy) DO UPDATE SET summary=excluded.summary").bind(key,fy,JSON.stringify(out)).run();return json({ok:true});
      }
      if(request.method==="POST"){
        const ref=String(body.ref||"").trim(),qty=body.qty,party=String(body.party||"").trim(),note=String(body.note||"").trim();
        if(!ref||ref.length>200||typeof qty!=="number"||!Number.isFinite(qty)||qty<=0||qty>1e9||party.length>200||note.length>1000)return json({error:"Invalid evidence"},400);
        const status='pending';if(!party)return json({error:'Issuer is required.'},400);
        const result=await env.DB.prepare("INSERT OR IGNORE INTO launch_evidence(company_id,fy,ref,qty,party,status,note) VALUES(?,?,?,?,?,?,?)").bind(key,fy,ref,qty,party,status,note).run();
        if(!result.meta.changes)return json({error:"Reference already exists for this financial year"},409);
        return json({ok:true},201);
      }
      if(request.method==="PATCH"){
        const id=Number(body.id),note=String(body.note||"").trim();
        if(!['reviewed','pending'].includes(body.status)||!Number.isSafeInteger(id)||id<=0||note.length>1000||!note)return json({error:"Review note required"},400);
        const r=await env.DB.prepare("UPDATE launch_evidence SET status=?,note=? WHERE id=? AND company_id=? AND fy=? AND party<>''").bind(body.status==="reviewed"?"reviewed":"pending",note,id,key,fy).run();
        return r.meta.changes?json({ok:true}):json({error:"Evidence not found or issuer missing"},404);
      }
      return json({error:"Method not allowed"},405);
    }

    if(u.pathname==="/api/me")return json({user});
    if(u.pathname==="/api/companies"&&request.method==="GET"){
      const r=await env.DB.prepare("SELECT id,legal_name,role,category,state,fy,created_at,updated_at FROM companies WHERE user_id=? ORDER BY created_at DESC").bind(user.id).all();
      return json(r.results||[]);
    }
    if(u.pathname==="/api/companies"&&request.method==="POST"){
      // Multiple company workspaces are available during the free pilot.
      const b=await readBody(request),legalName=String(b.legal_name||"").trim(),role=String(b.role||"").toLowerCase(),category=String(b.category||"").toUpperCase(),state=String(b.state||"").trim(),fy=String(b.fy||"2026-27");
      if(!legalName||legalName.length>200||state.length>100||!/^20\d{2}-\d{2}$/.test(fy)||Number(fy.slice(5))!==(Number(fy.slice(0,4))+1)%100||!roles.has(role)||!["I","II","III","IV"].includes(category))return json({error:"Company name, role and packaging category are required."},400);
      const companyIdType=await columnType(env,"companies","id");
      let id;
      if(isIntegerType(companyIdType)){
        const inserted=await env.DB.prepare("INSERT INTO companies(user_id,legal_name,role,category,state,fy,created_at,updated_at) VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)").bind(user.id,legalName,role,category,state,fy).run();
        id=inserted.meta?.last_row_id;
        if(id==null)throw new Error("Company insert did not return an integer row id");
      }else{
        id=crypto.randomUUID();
        await env.DB.prepare("INSERT INTO companies(id,user_id,legal_name,role,category,state,fy,created_at,updated_at) VALUES(?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)").bind(id,user.id,legalName,role,category,state,fy).run();
      }
      return json({id,legal_name:legalName,role,category,state,fy});
    }
    if(u.pathname==="/api/tasks"&&request.method==="GET"){
      const cid=u.searchParams.get('company_id');
      const company=await ownership(env,user.id,cid);if(!company)return json({error:'Company not found'},404);
      await seedWorkspaceTasks(env,company);
      const r=await env.DB.prepare("SELECT id,title,description,due_date,status,priority,source_url,created_at,completed_at FROM workspace_tasks WHERE company_id=? ORDER BY CASE WHEN status='open' THEN 0 ELSE 1 END, CASE WHEN due_date IS NULL THEN 1 ELSE 0 END, due_date ASC, id ASC").bind(company.id).all();
      return json(r.results||[]);
    }
    if(u.pathname==="/api/tasks"&&request.method==="POST"){
      const b=await readBody(request);const cid=b.company_id;const company=await ownership(env,user.id,cid);if(!company)return json({error:'Company not found'},404);
      await ensureWorkspaceTasks(env);
      const title=String(b.title||'').trim();if(!title||title.length>120)return json({error:'Enter a task title of up to 120 characters'},400);
      const description=String(b.description||'').trim();const due=b.due_date?String(b.due_date):null;if(description.length>2000||(due&&!/^\d{4}-\d{2}-\d{2}$/.test(due)))return json({error:'Invalid task description or date'},400);const priority=['low','normal','high'].includes(String(b.priority))?String(b.priority):'normal';
      await env.DB.prepare("INSERT INTO workspace_tasks(company_id,title,description,due_date,status,priority,source_url) VALUES(?,?,?,?,?,?,?)").bind(company.id,title,description,due,'open',priority,String(b.source_url||'')).run();
      return json({ok:true});
    }
    if(u.pathname==="/api/tasks"&&request.method==="PATCH"){
      const b=await readBody(request);const id=Number(b.id);const task=await env.DB.prepare("SELECT * FROM workspace_tasks WHERE id=?").bind(id).first();if(!task)return json({error:'Task not found'},404);
      const company=await ownership(env,user.id,task.company_id);if(!company)return json({error:'Task not found'},404);
      if(!['done','open'].includes(b.status))return json({error:'Invalid task status'},400);const status=b.status;await env.DB.prepare("UPDATE workspace_tasks SET status=?,completed_at=? WHERE id=?").bind(status,status==='done'?new Date().toISOString():null,id).run();
      return json({ok:true});
    }
    if(u.pathname==="/api/compliance"&&request.method==="GET"){
      const cid=u.searchParams.get("company_id");const company=await ownership(env,user.id,cid);if(!company)return json({error:"Company not found"},404);
      const profile=await env.DB.prepare("SELECT * FROM compliance_profiles WHERE company_id=?").bind(cid).first();
      return json({company,profile:profile||null});
    }
    if(u.pathname==="/api/compliance"&&request.method==="PUT"){
      const b=await readBody(request),company=await ownership(env,user.id,b.company_id);if(!company)return json({error:"Company not found"},404);
      for(const k of ["epr_target_tonnes","recycling_required_tonnes","recycled_content_rate"]){if(b[k]!=null&&(typeof b[k]!=="number"||!Number.isFinite(b[k])||b[k]<0))return json({error:"Invalid compliance value"},400);}
      const input=Number(b.input_tonnes);if(b.input_tonnes==null||typeof b.input_tonnes==='boolean'||String(b.input_tonnes).trim()===''||!Number.isFinite(input)||input<0)return json({error:"Enter a valid planning quantity."},400);
      if(b.planning_only===true){
        if(b.role!==company.role||b.category!==company.category||b.fy!==company.fy||company.fy!=="2026-27")return json({error:"Calculator result must match the selected company role, category and FY."},400);
        const r=await rules(env,request),rate=r.recycled_content_rate[company.category];
        await env.DB.prepare("INSERT INTO compliance_profiles(company_id,input_tonnes,recycled_content_rate,rule_version,source_url,verified_on) VALUES(?,?,?,?,?,?) ON CONFLICT(company_id) DO UPDATE SET input_tonnes=excluded.input_tonnes,recycled_content_rate=excluded.recycled_content_rate,rule_version=excluded.rule_version,source_url=excluded.source_url,verified_on=excluded.verified_on").bind(company.id,input,rate,r.version,r.source,r.verified_on).run();
        return json({ok:true});
      }
      const rate=b.recycled_content_rate==null?null:Number(b.recycled_content_rate),progress=Number(b.progress_tonnes||0);if(!Number.isFinite(progress)||progress<0)return json({error:"Enter a valid progress value."},400);
      await env.DB.prepare(`INSERT INTO compliance_profiles(company_id,input_tonnes,epr_target_tonnes,recycling_required_tonnes,recycled_content_rate,progress_tonnes,rule_version,source_url,verified_on) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(company_id) DO UPDATE SET input_tonnes=excluded.input_tonnes,epr_target_tonnes=excluded.epr_target_tonnes,recycling_required_tonnes=excluded.recycling_required_tonnes,recycled_content_rate=excluded.recycled_content_rate,progress_tonnes=excluded.progress_tonnes,rule_version=excluded.rule_version,source_url=excluded.source_url,verified_on=excluded.verified_on`).bind(company.id,input,b.epr_target_tonnes??null,b.recycling_required_tonnes??null,rate,progress,String(b.rule_version||""),String(b.source_url||""),String(b.verified_on||"")).run();
      return json({ok:true});
    }
    return json({error:"Not found"},404);
  }catch(e){
    if(e?.status===400||e?.status===413)return json({error:e.message},e.status);
    console.error("EPRTrack worker error",{path:u.pathname,method:request.method,name:e?.name||"Error"});
    return json({error:"Account service is temporarily unavailable. Please try again in a moment."},500);
  }
}}
