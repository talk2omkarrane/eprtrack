const CORS={"access-control-allow-origin":"*","access-control-allow-headers":"content-type,authorization","access-control-allow-methods":"GET,POST,PUT,DELETE,OPTIONS"};
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json",...CORS}});
const enc=new TextEncoder();
const roles=new Set(["producer","importer","brand-owner"]);
const labels={producer:"Producer",importer:"Importer","brand-owner":"Brand Owner"};
function hex(bytes){return [...new Uint8Array(bytes)].map(x=>x.toString(16).padStart(2,"0")).join("")}
async function hashPassword(password,saltHex){
  const salt=saltHex?Uint8Array.from(saltHex.match(/../g).map(x=>parseInt(x,16))):crypto.getRandomValues(new Uint8Array(16));
  const key=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:120000,hash:"SHA-256"},key,256);
  return `${hex(salt)}:${hex(bits)}`;
}
async function verifyPassword(password,stored){
  if(!stored||!stored.includes(":"))return false;
  const [,digest]=await hashPassword(password,stored.split(":")[0]);
  return digest===stored.split(":")[1];
}
function token(){return crypto.randomUUID()+"."+crypto.randomUUID()}
async function auth(request,env){
  const h=request.headers.get("authorization")||"";
  if(!h.startsWith("Bearer "))return null;
  return (await env.DB.prepare("SELECT u.id,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>datetime('now')").bind(h.slice(7)).first())||null;
}
async function rules(env,request){
  const r=await env.ASSETS.fetch(new URL("/rules.json",request.url));
  if(!r.ok)throw new Error("Rules unavailable");
  return r.json();
}
async function ownership(env,userId,companyId){
  return await env.DB.prepare("SELECT * FROM companies WHERE id=? AND user_id=?").bind(companyId,userId).first();
}
export default {async fetch(request,env){
  if(request.method==="OPTIONS")return new Response("",{headers:CORS});
  const u=new URL(request.url);
  try{
    if(u.pathname==="/api/health")return json({ok:true,service:"eprtrack",version:"v3-save-track"});

    if(u.pathname==="/api/calculator"&&request.method==="POST"){
      const b=await request.json(),role=String(b.role||"").toLowerCase(),cat=String(b.category||"").toUpperCase(),tonnes=Number(b.tonnes);
      if(!roles.has(role)||!["I","II","III","IV"].includes(cat)||!Number.isFinite(tonnes)||tonnes<0)return json({error:"Enter a valid role, category and quantity."},400);
      const r=await rules(env,request),rate=r.recycled_content_rate[cat];
      return json({fy:"2026-27",role,role_label:labels[role],category:cat,input_tonnes:tonnes,recycled_content_rate:rate,indicative_recycled_content_tonnes:rate==null?null:tonnes*rate,minimum_recycling_rate_of_applicable_target:r.minimum_recycling_of_applicable_target[cat],rule_version:r.version,source:r.source,verified_on:r.verified_on});
    }

    if(u.pathname==="/api/auth/register"&&request.method==="POST"){
      const b=await request.json(),email=String(b.email||"").trim().toLowerCase(),pw=String(b.password||"");
      if(!/^\S+@\S+\.\S+$/.test(email)||pw.length<8)return json({error:"Enter a valid email and a password of at least 8 characters."},400);
      if(await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first())return json({error:"An account with this email already exists."},409);
      const id=crypto.randomUUID(),passwordHash=await hashPassword(pw);
      await env.DB.prepare("INSERT INTO users(id,email,password_hash) VALUES(?,?,?)").bind(id,email,passwordHash).run();
      const t=token();await env.DB.prepare("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,datetime('now','+30 day'))").bind(t,id).run();
      return json({token:t,user:{id,email}});
    }

    if(u.pathname==="/api/auth/login"&&request.method==="POST"){
      const b=await request.json(),email=String(b.email||"").trim().toLowerCase(),pw=String(b.password||"");
      const usr=await env.DB.prepare("SELECT id,email,password_hash FROM users WHERE email=?").bind(email).first();
      if(!usr||!(await verifyPassword(pw,usr.password_hash)))return json({error:"Invalid email or password."},401);
      const t=token();await env.DB.prepare("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,datetime('now','+30 day'))").bind(t,usr.id).run();
      return json({token:t,user:{id:usr.id,email:usr.email}});
    }

    const user=await auth(request,env);
    if(u.pathname==="/api/auth/logout"&&request.method==="POST"){
      const h=request.headers.get("authorization")||"";if(h.startsWith("Bearer "))await env.DB.prepare("DELETE FROM sessions WHERE token=?").bind(h.slice(7)).run();
      return json({ok:true});
    }
    if(!user)return json({error:"Authentication required"},401);

    if(u.pathname==="/api/me")return json({user});

    if(u.pathname==="/api/companies"&&request.method==="GET"){
      const r=await env.DB.prepare("SELECT id,legal_name,role,category,state,fy,created_at,updated_at FROM companies WHERE user_id=? ORDER BY created_at DESC").bind(user.id).all();
      return json(r.results||[]);
    }
    if(u.pathname==="/api/companies"&&request.method==="POST"){
      const b=await request.json(),legalName=String(b.legal_name||"").trim(),role=String(b.role||"").toLowerCase(),category=String(b.category||"").toUpperCase(),state=String(b.state||"").trim(),fy=String(b.fy||"2026-27");
      if(!legalName||!roles.has(role)||!["I","II","III","IV"].includes(category))return json({error:"Company name, role and packaging category are required."},400);
      const id=crypto.randomUUID();
      await env.DB.prepare("INSERT INTO companies(id,user_id,legal_name,role,category,state,fy,created_at,updated_at) VALUES(?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)").bind(id,user.id,legalName,role,category,state,fy).run();
      return json({id,legal_name:legalName,role,category,state,fy});
    }

    if(u.pathname==="/api/compliance"&&request.method==="GET"){
      const cid=u.searchParams.get("company_id");const company=await ownership(env,user.id,cid);if(!company)return json({error:"Company not found"},404);
      const profile=await env.DB.prepare("SELECT * FROM compliance_profiles WHERE company_id=?").bind(cid).first();
      return json({company,profile:profile||null});
    }
    if(u.pathname==="/api/compliance"&&request.method==="PUT"){
      const b=await request.json(),company=await ownership(env,user.id,b.company_id);if(!company)return json({error:"Company not found"},404);
      const input=Number(b.input_tonnes);if(!Number.isFinite(input)||input<0)return json({error:"Enter a valid planning quantity."},400);
      const rate=b.recycled_content_rate==null?null:Number(b.recycled_content_rate);
      const progress=Number(b.progress_tonnes||0);if(!Number.isFinite(progress)||progress<0)return json({error:"Enter a valid progress value."},400);
      await env.DB.prepare(`INSERT INTO compliance_profiles(company_id,input_tonnes,epr_target_tonnes,recycling_required_tonnes,recycled_content_rate,progress_tonnes,rule_version,source_url,verified_on) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(company_id) DO UPDATE SET input_tonnes=excluded.input_tonnes,epr_target_tonnes=excluded.epr_target_tonnes,recycling_required_tonnes=excluded.recycling_required_tonnes,recycled_content_rate=excluded.recycled_content_rate,progress_tonnes=excluded.progress_tonnes,rule_version=excluded.rule_version,source_url=excluded.source_url,verified_on=excluded.verified_on`).bind(company.id,input,b.epr_target_tonnes??null,b.recycling_required_tonnes??null,rate,progress,String(b.rule_version||""),String(b.source_url||""),String(b.verified_on||"")).run();
      return json({ok:true});
    }
    return json({error:"Not found"},404);
  }catch(e){return json({error:"Server error"},500)}
}}
