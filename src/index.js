export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/health") return Response.json({ok:true,service:"eprtrack"});
    if (url.pathname === "/api/plans") {
      const {results}=await env.DB.prepare("SELECT code,name,monthly_price_inr FROM plans WHERE active=1 ORDER BY monthly_price_inr").all();
      return Response.json({plans:results});
    }
    if (url.pathname === "/api/calculator" && request.method === "POST") {
      const body=await request.json(), category=String(body.category||"").toUpperCase(), tonnes=Number(body.tonnes);
      const rules=await fetch(new URL("/rules.json",request.url)).then(r=>r.json());
      if (!["I","II","III","IV"].includes(category)||!Number.isFinite(tonnes)||tonnes<0)
        return Response.json({error:"Enter a valid category and non-negative plastic quantity."},{status:400});
      const rate=rules.recycled_content_rate[category], minimum=rules.minimum_recycling_of_applicable_target[category];
      return Response.json({
        fy:"2026-27",category,input_tonnes:tonnes,recycled_content_rate:rate,
        indicative_recycled_content_tonnes:rate==null?null:tonnes*rate,
        minimum_recycling_rate_of_applicable_target:minimum,
        rule_version:rules.version,source:rules.source,verified_on:rules.verified_on,
        disclaimer:"Indicative planning calculation only. It is not an official CPCB filing or determination of legal applicability."
      });
    }
    return env.ASSETS.fetch(request);
  }
};