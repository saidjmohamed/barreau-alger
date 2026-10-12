import { createClient } from "npm:@supabase/supabase-js@2.54.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { ...corsHeaders, "Content-Type": "application/json" },
});
const validUsername = (s: string) => /^[a-zA-Z0-9._-]{3,40}$/.test(s);

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  const url = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const authorization = req.headers.get("Authorization");
  if (!url || !serviceKey || !authorization) return json({ error: "يلزم تسجيل الدخول." }, 401);
  const db = createClient(url, serviceKey, { auth: { autoRefreshToken: false, persistSession: false } });
  const token = authorization.replace(/^Bearer\s+/i, "");
  const { data: authData, error: authError } = await db.auth.getUser(token);
  const user = authData.user;
  if (authError || !user || user.app_metadata?.role !== "admin" || user.app_metadata?.active !== true)
    return json({ error: "هذه العملية متاحة للأدمن العام النشط فقط." }, 403);
  const { data: adminProfile } = await db.from("profiles").select("role,active,court_id").eq("id", user.id).maybeSingle();
  if (!adminProfile || adminProfile.role !== "admin" || !adminProfile.active || adminProfile.court_id !== null)
    return json({ error: "ملف الأدمن العام غير صالح." }, 403);

  let b: Record<string, unknown>;
  try { b = await req.json(); } catch { return json({ error: "البيانات غير صالحة." }, 400); }
  const action = String(b.action || "");
  if (action === "list") {
    const { data, error } = await db.from("profiles")
      .select("id,username,display_name,court_id,active,courts(name)")
      .eq("role", "court_admin").order("display_name");
    if (error) return json({ error: "تعذر تحميل حسابات مسؤولي الهيئات." }, 500);
    return json({ ok: true, accounts: data || [] });
  }

  if (action === "create") {
    const username = String(b.username || "").trim();
    const displayName = String(b.display_name || "").trim();
    const password = String(b.password || "");
    const courtId = String(b.court_id || "").trim();
    if (!validUsername(username) || displayName.length < 2 || displayName.length > 160 ||
        password.length < 10 || password.length > 128 ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(courtId))
      return json({ error: "أدخل اسم مستخدم من 3 إلى 40 حرفًا، وكلمة مرور من 10 أحرف على الأقل، واسم المسؤول والهيئة." }, 400);
    const { data: court } = await db.from("courts").select("id,name,active").eq("id", courtId).maybeSingle();
    if (!court?.active) return json({ error: "الهيئة غير موجودة أو غير مفعلة." }, 400);
    const { data: existing } = await db.from("profiles").select("id").eq("court_id", courtId).eq("role", "court_admin").maybeSingle();
    if (existing) return json({ error: "لهذه الهيئة حساب مسؤول بالفعل." }, 409);
    const { data: taken } = await db.from("profiles").select("id").ilike("username", username).maybeSingle();
    if (taken) return json({ error: "اسم المستخدم مستخدم بالفعل." }, 409);
    // Supabase Auth remains responsible for password hashing; the email is an internal login identifier.
    const internalEmail = username.toLowerCase() + "@alger.com";
    const { data: created, error: createError } = await db.auth.admin.createUser({
      email: internalEmail, password, email_confirm: true,
      app_metadata: { role: "court_admin", court_id: courtId, active: true },
      user_metadata: { full_name: displayName, username: username.toLowerCase() },
    });
    if (createError || !created.user) return json({ error: createError?.message || "تعذر إنشاء الحساب." }, 400);
    const { error: profileError } = await db.from("profiles").insert({
      id: created.user.id, display_name: displayName, username: username.toLowerCase(),
      role: "court_admin", court_id: courtId, active: true,
    });
    if (profileError) {
      await db.auth.admin.deleteUser(created.user.id);
      return json({ error: "تعذر حفظ الحساب؛ تم التراجع عن إنشائه." }, 500);
    }
    return json({ ok: true, username: username.toLowerCase(), display_name: displayName, court_name: court.name }, 201);
  }

  const accountId = String(b.account_id || "");
  const { data: account, error: accountError } = await db.from("profiles")
    .select("id,role,court_id,username,display_name,active").eq("id", accountId).maybeSingle();
  if (accountError || !account || account.role !== "court_admin")
    return json({ error: "حساب مسؤول المحكمة غير موجود." }, 404);

  if (action === "set_password") {
    const password = String(b.password || "");
    if (password.length < 10 || password.length > 128)
      return json({ error: "كلمة المرور يجب أن تتكون من 10 أحرف على الأقل." }, 400);
    const { error } = await db.auth.admin.updateUserById(account.id, { password });
    if (error) return json({ error: "تعذر تغيير كلمة المرور." }, 400);
    return json({ ok: true, message: "تم تغيير كلمة المرور." });
  }
  if (action === "delete") {
    // Remove the application profile first: this project has no FK cascade from profiles.id to auth.users.id.
    // Keep the court and all court-request data untouched.
    const { data: removedProfile, error: profileDeleteError } = await db.from("profiles")
      .delete().eq("id", account.id).select("id").maybeSingle();
    if (profileDeleteError || !removedProfile)
      return json({ error: "تعذر إزالة ملف المسؤول من التطبيق؛ لم يُحذف حساب المصادقة." }, 400);

    const { error: authDeleteError } = await db.auth.admin.deleteUser(account.id);
    if (authDeleteError) {
      // Restore the profile if Auth deletion fails, avoiding a half-deleted account.
      const { error: restoreError } = await db.from("profiles").insert({
        id: account.id,
        username: account.username,
        display_name: account.display_name,
        role: account.role,
        court_id: account.court_id,
        active: account.active,
      });
      if (restoreError) return json({ error: "تعذر حذف حساب المصادقة وفشل استرجاع ملف المسؤول؛ يلزم تدخل إداري." }, 500);
      return json({ error: "تعذر حذف حساب المصادقة؛ أُعيد ملف المسؤول ولم يُحذف الحساب." }, 400);
    }
    return json({ ok: true, message: "تم حذف حساب المسؤول وملفه؛ بقيت الهيئة وبيانات الطلبات دون تغيير." });
  }
  return json({ error: "عملية غير معروفة." }, 400);
});
