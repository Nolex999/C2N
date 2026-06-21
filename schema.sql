-- ============================================================
-- GYD (Global Device Scanner) — Supabase Schema
-- Run this in Supabase SQL Editor
-- ============================================================

-- 1. Users table (profiles linked to auth.users)
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  username TEXT,
  avatar_url TEXT DEFAULT '',
  bio TEXT DEFAULT '',
  community TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT now()
);

-- 2. Invitation codes
CREATE TABLE invite_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code TEXT UNIQUE NOT NULL,
  status TEXT DEFAULT 'active' CHECK (status IN ('active', 'used', 'revoked')),
  issuer UUID REFERENCES users(id),
  used_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT now(),
  used_at TIMESTAMPTZ
);

-- 3. Scan results (one per scan run)
CREATE TABLE scan_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) NOT NULL,
  total_scanned INTEGER DEFAULT 0,
  results_count INTEGER DEFAULT 0,
  creds_count INTEGER DEFAULT 0,
  open_count INTEGER DEFAULT 0,
  region TEXT DEFAULT 'internet',
  ports TEXT DEFAULT 'fast',
  created_at TIMESTAMPTZ DEFAULT now()
);

-- 4. Individual device results from scans
CREATE TABLE scan_result_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  result_id UUID REFERENCES scan_results(id) ON DELETE CASCADE NOT NULL,
  item_index INTEGER,
  ip TEXT,
  port INTEGER,
  url TEXT,
  device TEXT,
  no_auth BOOLEAN DEFAULT false,
  auth_found BOOLEAN DEFAULT false,
  username TEXT,
  password TEXT,
  note TEXT,
  status_code INTEGER,
  country TEXT,
  country_code TEXT,
  region_name TEXT,
  city TEXT,
  lat DOUBLE PRECISION,
  lon DOUBLE PRECISION,
  org TEXT,
  isp TEXT,
  as_info TEXT,
  broken BOOLEAN DEFAULT false,
  broken_at TIMESTAMPTZ
);

-- 5. Audit logs
CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  action TEXT NOT NULL,
  timestamp TIMESTAMPTZ DEFAULT now(),
  target_user UUID REFERENCES users(id),
  actor UUID REFERENCES users(id)
);

-- 6. Communities
CREATE TABLE communities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT now(),
  owner_id UUID REFERENCES users(id)
);

-- Profiles (extended user info, linked 1:1 to users)
CREATE TABLE profiles (
  id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  display_name TEXT,
  avatar_url TEXT DEFAULT '',
  bio TEXT DEFAULT '',
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- ============================================================
-- INDEXES
-- ============================================================
CREATE INDEX idx_scan_results_user_id ON scan_results(user_id);
CREATE INDEX idx_scan_results_created_at ON scan_results(created_at DESC);
CREATE INDEX idx_scan_result_items_result_id ON scan_result_items(result_id);
CREATE INDEX idx_scan_result_items_broken ON scan_result_items(broken);
CREATE INDEX idx_invite_codes_code ON invite_codes(code);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);

-- ============================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================

-- Users: each user can read their own record
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users_insert_own" ON users FOR INSERT WITH CHECK (id = auth.uid());
CREATE POLICY "users_select_own" ON users FOR SELECT USING (id = auth.uid());
CREATE POLICY "users_update_own" ON users FOR UPDATE USING (id = auth.uid());

-- Scan results: owner can CRUD
ALTER TABLE scan_results ENABLE ROW LEVEL SECURITY;
CREATE POLICY "scan_results_select_own" ON scan_results FOR SELECT USING (user_id = auth.uid());
CREATE POLICY "scan_results_insert_own" ON scan_results FOR INSERT WITH CHECK (user_id = auth.uid());
CREATE POLICY "scan_results_delete_own" ON scan_results FOR DELETE USING (user_id = auth.uid());

-- Scan result items: access via result ownership
ALTER TABLE scan_result_items ENABLE ROW LEVEL SECURITY;
CREATE POLICY "items_select_own" ON scan_result_items
  FOR SELECT USING (
    EXISTS (SELECT 1 FROM scan_results WHERE id = result_id AND user_id = auth.uid())
  );
CREATE POLICY "items_insert_own" ON scan_result_items
  FOR INSERT WITH CHECK (
    EXISTS (SELECT 1 FROM scan_results WHERE id = result_id AND user_id = auth.uid())
  );
CREATE POLICY "items_update_own" ON scan_result_items
  FOR UPDATE USING (
    EXISTS (SELECT 1 FROM scan_results WHERE id = result_id AND user_id = auth.uid())
  );
CREATE POLICY "items_delete_own" ON scan_result_items
  FOR DELETE USING (
    EXISTS (SELECT 1 FROM scan_results WHERE id = result_id AND user_id = auth.uid())
  );

-- Invite codes: anon can read active codes (for registration)
ALTER TABLE invite_codes ENABLE ROW LEVEL SECURITY;
CREATE POLICY "invite_codes_select_active" ON invite_codes
  FOR SELECT USING (status = 'active');
CREATE POLICY "invite_codes_update_own" ON invite_codes
  FOR UPDATE USING (
    EXISTS (SELECT 1 FROM users WHERE id = auth.uid())
  );

-- ============================================================
-- TRIGGER: automatically create users row when auth.users signs up
-- ============================================================
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO users (id, email, username)
  VALUES (NEW.id, NEW.email, split_part(NEW.email, '@', 1));
  INSERT INTO profiles (id)
  VALUES (NEW.id);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION handle_new_user();
