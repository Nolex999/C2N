-- GYD Schema — run this in Supabase SQL Editor

CREATE TABLE users (
  id UUID PRIMARY KEY,
  email TEXT NOT NULL,
  username TEXT DEFAULT '',
  avatar_url TEXT DEFAULT '',
  bio TEXT DEFAULT '',
  community TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE invite_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code TEXT UNIQUE NOT NULL,
  status TEXT DEFAULT 'active' CHECK (status IN ('active','used','revoked')),
  issuer TEXT,
  used_by TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  used_at TIMESTAMPTZ
);

CREATE TABLE scan_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) NOT NULL,
  total_scanned INT DEFAULT 0,
  results_count INT DEFAULT 0,
  creds_count INT DEFAULT 0,
  open_count INT DEFAULT 0,
  region TEXT DEFAULT 'internet',
  ports TEXT DEFAULT 'fast',
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE scan_result_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  result_id UUID REFERENCES scan_results(id) ON DELETE CASCADE NOT NULL,
  item_index INT,
  ip TEXT,
  port INT,
  url TEXT,
  device TEXT,
  no_auth BOOLEAN DEFAULT false,
  auth_found BOOLEAN DEFAULT false,
  username TEXT,
  password TEXT,
  note TEXT,
  status_code INT,
  country TEXT,
  country_code TEXT,
  region_name TEXT,
  city TEXT,
  lat FLOAT8,
  lon FLOAT8,
  org TEXT,
  isp TEXT,
  as_info TEXT,
  broken BOOLEAN DEFAULT false,
  broken_at TIMESTAMPTZ
);

CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  action TEXT NOT NULL,
  timestamp TIMESTAMPTZ DEFAULT now(),
  target_user TEXT,
  actor TEXT
);

-- Indexes
CREATE INDEX idx_scan_results_user ON scan_results(user_id);
CREATE INDEX idx_scan_results_time ON scan_results(created_at DESC);
CREATE INDEX idx_items_result ON scan_result_items(result_id);
CREATE INDEX idx_items_broken ON scan_result_items(broken);
CREATE INDEX idx_invite_code ON invite_codes(code);
CREATE INDEX idx_audit_time ON audit_logs(timestamp DESC);

-- RLS
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_result_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE invite_codes ENABLE ROW LEVEL SECURITY;

CREATE POLICY "users_all" ON users FOR ALL USING (id = auth.uid()) WITH CHECK (id = auth.uid());
CREATE POLICY "results_all" ON scan_results FOR ALL USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
CREATE POLICY "items_all" ON scan_result_items FOR ALL USING (
  EXISTS (SELECT 1 FROM scan_results WHERE id = result_id AND user_id = auth.uid())
) WITH CHECK (
  EXISTS (SELECT 1 FROM scan_results WHERE id = result_id AND user_id = auth.uid())
);
CREATE POLICY "invite_read" ON invite_codes FOR SELECT USING (status = 'active');

-- Auto-create users row on signup
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO users (id, email, username)
  VALUES (NEW.id, NEW.email, split_part(NEW.email, '@', 1));
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION handle_new_user();
