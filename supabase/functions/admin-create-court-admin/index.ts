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
function temporaryPassword(length = 26) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => chars[b % chars.length]).join("");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const url = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const authorization = req.headers.get("Authorization");
  if (!url || !serviceKey || !authorization) return json({ error: "يلزم إعداد الخدمة وتسجيل الدخول." }, 401);

  const adminClient = createClient(url, serviceKey, { auth: { autoRefreshToken: false, persistSession: false } });
  const token = authorization.replace(/^Bearer\s+/i, "");
  const { data: authData, error: authError } = await adminClient.auth.getUser(token);
  const user = authData.user;
  if (authError || !user || user.app_metadata?.role !== "admin" || user.app_metadata?.active !== true) {
    return json({ error: "غير مصرح. يلزم حساب الأدمن العام النشط." }, 403);
  }
  const { data: adminProfile, error: adminProfileError } = await adminClient
    .from("profiles").select("role,active,court_id").eq("id", user.id).maybeSingle();
  if (adminProfileError || !adminProfile || adminProfile.role !== "admin" || !adminProfile.active || adminProfile.court_id !== null) {
    return json({ error: "ملف الأدمن العام غير صالح." }, 403);
  }

  let body: { email?: string; display_name?: string; court_id?: string };
  try { body = await req.json(); } catch { return json({ error: "بيانات الطلب غير صالحة." }, 400); }
  const email = String(body.email || "").trim().toLowerCase();
  const displayName = String(body.display_name || "").trim();
  const courtId = String(body.court_id || "").trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || displayName.length < 2 || displayName.length > 160 ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(courtId)) {
    return json({ error: "أدخل اسم المسؤول وبريده الإلكتروني والهيئة بصورة صحيحة." }, 400);
  }

  const { data: court, error: courtError } = await adminClient.from("courts")
    .select("id,name,active").eq("id", courtId).maybeSingle();
  if (courtError || !court || !court.active) return json({ error: "الهيئة غير موجودة أو غير مفعلة." }, 400);

  const { data: existing, error: existingError } = await adminClient.from("profiles")
    .select("id").eq("court_id", court.id).eq("role", "court_admin").maybeSingle();
  if (existingError) return json({ error: "تعذر التحقق من حساب الهيئة." }, 500);
  if (existing) return json({ error: "يوجد أدمن لهذه الهيئة بالفعل." }, 409);

  const password = temporaryPassword();
  const { data: created, error: createError } = await adminClient.auth.admin.createUser({
    email, password, email_confirm: true,
    app_metadata: { role: "court_admin", court_id: court.id, active: true },
    user_metadata: { full_name: displayName },
  });
  if (createError || !created.user) return json({ error: createError?.message || "تعذر إنشاء الحساب." }, 400);

  const { error: profileError } = await adminClient.from("profiles").insert({
    id: created.user.id, display_name: displayName, role: "court_admin", court_id: court.id, active: true,
  });
  if (profileError) {
    await adminClient.auth.admin.deleteUser(created.user.id);
    return json({ error: "تعذر حفظ ملف الأدمن؛ تم التراجع عن إنشاء الحساب." }, 500);
  }

  return json({
    ok: true, email, display_name: displayName, court_name: court.name, temporary_password: password,
    message: "تم إنشاء الحساب. انسخ كلمة المرور المؤقتة وسلّمها للمسؤول بطريقة آمنة.",
  }, 201);
});
