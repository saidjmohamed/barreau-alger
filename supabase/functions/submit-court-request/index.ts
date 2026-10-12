import { createClient } from "npm:@supabase/supabase-js@2.54.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}
const validDate = (value: string) => /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(value));

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const url = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !serviceKey) return json({ error: "الخدمة غير مهيأة." }, 503);

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return json({ error: "الطلب غير صالح." }, 400); }

  // Honeypot field for basic bot filtering; add a CAPTCHA before public launch.
  if (String(body.website || "").trim()) return json({ ok: true, message: "تم استلام الطلب." }, 200);

  const courtId = String(body.court_id || "").trim();
  const lawyerName = String(body.lawyer_full_name || "").trim();
  const accreditationDate = String(body.lawyer_accreditation_date || "").trim();
  const requestType = String(body.request_type || "");
  const sessionType = String(body.session_type || "");
  const hearingDate = String(body.hearing_date || "").trim();
  const caseNumber = String(body.case_number || "").trim();
  const note = String(body.note || "").trim();

  const allowedRequestTypes = new Set(["advance", "postpone"]);
  const allowedSessionTypes = new Set([
    "misdemeanor", "civil", "real_estate", "family", "commercial",
    "administrative", "urgent", "felonies", "violations", "social", "other"
  ]);
  if (!/^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(courtId) ||
      lawyerName.length < 4 || lawyerName.length > 160 ||
      !validDate(accreditationDate) || !validDate(hearingDate) ||
      !allowedRequestTypes.has(requestType) || !allowedSessionTypes.has(sessionType) ||
      caseNumber.length > 120 || note.length > 1000) {
    return json({ error: "يرجى مراجعة الحقول المطلوبة والتأكد من صحة التواريخ." }, 400);
  }

  const db = createClient(url, serviceKey, { auth: { autoRefreshToken: false, persistSession: false } });
  const { data: court, error: courtError } = await db
    .from("courts").select("id,name,active").eq("id", courtId).maybeSingle();
  if (courtError || !court || !court.active) return json({ error: "الهيئة القضائية غير متاحة حاليًا." }, 400);

  const { data, error } = await db.from("court_requests").insert({
    court_id: court.id,
    case_number: caseNumber || null,
    lawyer_full_name: lawyerName,
    lawyer_accreditation_date: accreditationDate,
    request_type: requestType,
    session_type: sessionType,
    hearing_date: hearingDate,
    note: note || null,
    status: "new",
    created_by: null,
  }).select("id").single();

  if (error || !data) return json({ error: "تعذر تسجيل الطلب الآن. يرجى المحاولة لاحقًا." }, 500);
  return json({ ok: true, request_id: data.id, court_name: court.name, message: "تم إرسال الطلب إلى الهيئة القضائية المختارة." }, 201);
});
