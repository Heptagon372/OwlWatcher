import { createClient } from "@supabase/supabase-js";

// anon 키만 쓴다. 읽기는 RLS 가 막고, 쓰기는 heartbeat Edge Function 만 한다 —
// 콘솔이 service_role 을 들고 있으면 브라우저에 유출되는 순간 전부 끝난다.
const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

export const configured = Boolean(url && anon);

export const supabase = configured
  ? createClient(url!, anon!, { auth: { persistSession: true } })
  : null;
