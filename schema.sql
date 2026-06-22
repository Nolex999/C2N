-- GYD Schema — run this in the Supabase SQL Editor
-- Safe to re-run: drops existing tables first

DROP TABLE IF EXISTS scan_result_items CASCADE;
DROP TABLE IF EXISTS scan_results CASCADE;
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS invite_codes CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- ─── Tables ───────────────────────────────────────────────────────────────────

CREATE TABLE users (
  id          UUID        PRIMARY KEY,           -- matches auth.users.id
  email       TEXT        NOT NULL,
  username    TEXT        DEFAULT '',
  avatar_url  TEXT        DEFAULT '',
  bio         TEXT        DEFAULT '',
  created_at  TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE invite_codes (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  code        TEXT        UNIQUE NOT NULL,
  status      TEXT        DEFAULT 'active' CHECK (status IN ('active', 'used', 'revoked')),
  issuer      UUID,                              -- references auth.users.id (nullable)
  used_by     UUID,                              -- references auth.users.id (nullable)
  created_at  TIMESTAMPTZ DEFAULT now(),
  used_at     TIMESTAMPTZ
);

CREATE TABLE scan_results (
  id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  total_scanned  INT         DEFAULT 0,
  results_count  INT         DEFAULT 0,
  creds_count    INT         DEFAULT 0,
  open_count     INT         DEFAULT 0,
  region         TEXT        DEFAULT 'internet',
  ports          TEXT        DEFAULT 'fast',
  created_at     TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE scan_result_items (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  result_id    UUID        NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
  item_index   INT,
  ip           TEXT,
  port         INT,
  url          TEXT,
  device       TEXT,
  no_auth      BOOLEAN     DEFAULT false,
  auth_found   BOOLEAN     DEFAULT false,
  username     TEXT,
  password     TEXT,
  note         TEXT,
  status_code  INT,
  country      TEXT,
  country_code TEXT,
  region_name  TEXT,
  city         TEXT,
  lat          FLOAT8,
  lon          FLOAT8,
  org          TEXT,
  isp          TEXT,
  as_info      TEXT,
  broken       BOOLEAN     DEFAULT false,
  broken_at    TIMESTAMPTZ
);

CREATE TABLE audit_logs (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  action      TEXT        NOT NULL,
  actor       UUID,
  target_user UUID,
  created_at  TIMESTAMPTZ DEFAULT now()
);

-- ─── Indexes ──────────────────────────────────────────────────────────────────

CREATE INDEX idx_scan_results_user ON scan_results(user_id);
CREATE INDEX idx_scan_results_time ON scan_results(created_at DESC);
CREATE INDEX idx_items_result      ON scan_result_items(result_id);
CREATE INDEX idx_items_broken      ON scan_result_items(broken);
CREATE INDEX idx_invite_code       ON invite_codes(code);
CREATE INDEX idx_invite_status     ON invite_codes(status);
CREATE INDEX idx_audit_time        ON audit_logs(created_at DESC);

-- ─── Row-Level Security ───────────────────────────────────────────────────────

ALTER TABLE users             ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_results      ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_result_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE invite_codes      ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs        ENABLE ROW LEVEL SECURITY;

-- users: each user can only see/modify their own row
CREATE POLICY "users_self" ON users
  FOR ALL
  USING  (id = auth.uid())
  WITH CHECK (id = auth.uid());

-- scan_results: owned by authenticated user
CREATE POLICY "results_owner" ON scan_results
  FOR ALL
  USING  (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());

-- scan_result_items: accessible if the parent scan_result belongs to the user
CREATE POLICY "items_owner" ON scan_result_items
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM scan_results
      WHERE scan_results.id = result_id
        AND scan_results.user_id = auth.uid()
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM scan_results
      WHERE scan_results.id = result_id
        AND scan_results.user_id = auth.uid()
    )
  );

-- invite_codes:
--   • anyone (even anon) can SELECT an active code (needed during registration check)
--   • authenticated users can INSERT new codes (admin use via service-role or authenticated)
--   • authenticated users can UPDATE codes (mark as used)
--   • no DELETE allowed via RLS (only service role can delete)
CREATE POLICY "invite_read_active" ON invite_codes
  FOR SELECT
  USING (status = 'active');

CREATE POLICY "invite_read_all_authed" ON invite_codes
  FOR SELECT
  TO authenticated
  USING (true);   -- lets logged-in users list all codes in admin panel

CREATE POLICY "invite_insert_authed" ON invite_codes
  FOR INSERT
  TO authenticated
  WITH CHECK (true);

CREATE POLICY "invite_update_authed" ON invite_codes
  FOR UPDATE
  TO authenticated
  USING (true)
  WITH CHECK (true);

-- audit_logs: service-role only (no user policy needed; backend uses service key)

-- ─── Trigger: auto-create users row on Supabase Auth signup ──────────────────

CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.users (id, email, username)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'username', split_part(NEW.email, '@', 1))
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION handle_new_user();
