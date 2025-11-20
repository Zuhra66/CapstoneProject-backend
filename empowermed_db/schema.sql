-- =========================================================
-- EmpowerMed schema (UUID users, pg_trgm enabled, drop-safe)
-- =========================================================

-- ---------- Clean drops (child tables → parents) ----------
DROP TRIGGER IF EXISTS t_posts_upd        ON blog_posts;
DROP TRIGGER IF EXISTS t_appointments_upd ON appointments;
DROP TRIGGER IF EXISTS t_products_upd     ON products;
DROP TRIGGER IF EXISTS t_profiles_upd     ON profiles;
DROP TRIGGER IF EXISTS t_users_upd        ON users;

DROP FUNCTION IF EXISTS touch_updated_at();

DROP TABLE IF EXISTS audit_logs         CASCADE;
DROP TABLE IF EXISTS contact_messages   CASCADE;
DROP TABLE IF EXISTS blog_posts         CASCADE;
DROP TABLE IF EXISTS user_memberships   CASCADE;
DROP TABLE IF EXISTS membership_plans   CASCADE;
DROP TABLE IF EXISTS appointments       CASCADE;
DROP TABLE IF EXISTS locations          CASCADE;
DROP TABLE IF EXISTS services           CASCADE;
DROP TABLE IF EXISTS providers          CASCADE;
DROP TABLE IF EXISTS product_tags       CASCADE;
DROP TABLE IF EXISTS products           CASCADE;
DROP TABLE IF EXISTS tags               CASCADE;
DROP TABLE IF EXISTS categories         CASCADE;
DROP TABLE IF EXISTS profiles           CASCADE;
DROP TABLE IF EXISTS users              CASCADE;

DROP TYPE IF EXISTS post_status         CASCADE;
DROP TYPE IF EXISTS membership_status   CASCADE;
DROP TYPE IF EXISTS appt_status         CASCADE;

-- ---------- Extensions ----------
CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;    -- case-insensitive text
CREATE EXTENSION IF NOT EXISTS pg_trgm;   -- trigram index ops (gin_trgm_ops)

-- ---------- Reference data ----------
CREATE TABLE categories (
  id          SERIAL PRIMARY KEY,
  name        CITEXT UNIQUE NOT NULL,      -- 'Skincare', 'Beverage', 'Supplement'
  slug        CITEXT UNIQUE NOT NULL
);

CREATE TABLE tags (
  id          SERIAL PRIMARY KEY,
  name        CITEXT UNIQUE NOT NULL       -- 'Hydration', 'Radiance', 'Complete Set', etc.
);

-- ---------- Users & Profiles (Auth0-friendly) ----------
CREATE TABLE users (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  auth_provider   TEXT NOT NULL DEFAULT 'auth0',  -- 'auth0','email','google', etc.
  auth_sub        TEXT UNIQUE NOT NULL,           -- e.g. 'auth0|abc123'
  email           CITEXT UNIQUE,
  name            TEXT,
  role            TEXT NOT NULL DEFAULT 'user',   -- 'user','admin','provider'
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Trigram index for faster ILIKE/email search
CREATE INDEX users_email_trgm ON users USING GIN (email gin_trgm_ops);

CREATE TABLE profiles (
  user_id       UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  phone         TEXT,
  date_of_birth DATE,
  gender        TEXT,
  address_line1 TEXT,
  address_line2 TEXT,
  city          TEXT,
  region        TEXT,
  postal_code   TEXT,
  country       TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- Products (metadata + external shop link) ----------
CREATE TABLE products (
  id            SERIAL PRIMARY KEY,
  name          TEXT NOT NULL,
  slug          CITEXT UNIQUE NOT NULL,
  category_id   INT REFERENCES categories(id),
  price_cents   INT,                               -- store as integer cents for accuracy
  image_url     TEXT,
  external_url  TEXT NOT NULL,                     -- link to shop page
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX products_category_idx ON products (category_id);
CREATE INDEX products_active_idx   ON products (is_active);
CREATE INDEX products_name_trgm    ON products USING GIN (name gin_trgm_ops);

CREATE TABLE product_tags (
  product_id INT REFERENCES products(id) ON DELETE CASCADE,
  tag_id     INT REFERENCES tags(id)     ON DELETE CASCADE,
  PRIMARY KEY (product_id, tag_id)
);

-- ---------- Providers / Services / Appointments ----------
CREATE TABLE providers (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID UNIQUE REFERENCES users(id) ON DELETE SET NULL, -- optional link to a user
  display_name TEXT NOT NULL,
  bio          TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE services (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         TEXT NOT NULL,              -- e.g., 'Consultation', 'IV Therapy'
  slug         CITEXT UNIQUE NOT NULL,
  description  TEXT,
  duration_min INT NOT NULL,               -- e.g., 30, 60
  price_cents  INT,
  is_active    BOOLEAN NOT NULL DEFAULT TRUE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE locations (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         TEXT NOT NULL,
  address1     TEXT,
  address2     TEXT,
  city         TEXT,
  region       TEXT,
  postal_code  TEXT,
  country      TEXT,
  tz           TEXT NOT NULL DEFAULT 'America/Los_Angeles'
);

-- Appointment statuses: 'available','booked','cancelled','completed'
CREATE TYPE appt_status AS ENUM ('available','booked','cancelled','completed');

CREATE TABLE appointments (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  service_id    UUID REFERENCES services(id)   ON DELETE RESTRICT,
  provider_id   UUID REFERENCES providers(id)  ON DELETE RESTRICT,
  location_id   UUID REFERENCES locations(id)  ON DELETE SET NULL,
  user_id       UUID REFERENCES users(id)      ON DELETE SET NULL, -- null until booked
  start_time    TIMESTAMPTZ NOT NULL,
  end_time      TIMESTAMPTZ NOT NULL,
  status        appt_status NOT NULL DEFAULT 'available',
  notes         TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (end_time > start_time)
);
CREATE INDEX appt_time_idx     ON appointments (start_time, end_time);
CREATE INDEX appt_status_idx   ON appointments (status);
CREATE INDEX appt_provider_idx ON appointments (provider_id);

-- ---------- Memberships ----------
CREATE TYPE membership_status AS ENUM ('active','paused','canceled');

CREATE TABLE membership_plans (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         TEXT NOT NULL,                 -- e.g., 'Empower Basic', 'Empower Plus'
  slug         CITEXT UNIQUE NOT NULL,
  price_cents  INT NOT NULL,
  interval     TEXT NOT NULL DEFAULT 'month', -- 'month','year'
  description  TEXT,
  is_active    BOOLEAN NOT NULL DEFAULT TRUE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_memberships (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
  plan_id      UUID REFERENCES membership_plans(id) ON DELETE RESTRICT,
  status       membership_status NOT NULL DEFAULT 'active',
  start_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  end_at       TIMESTAMPTZ,
  external_ref TEXT,         -- e.g., Stripe subs id
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX user_memberships_user_idx ON user_memberships (user_id);

-- ---------- Blog / CMS light ----------
CREATE TYPE post_status AS ENUM ('draft','published','archived');

CREATE TABLE blog_posts (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  author_id    UUID REFERENCES users(id) ON DELETE SET NULL,
  title        TEXT NOT NULL,
  slug         CITEXT UNIQUE NOT NULL,
  content_md   TEXT,                         -- markdown/MDX
  status       post_status NOT NULL DEFAULT 'draft',
  published_at TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX blog_status_idx ON blog_posts (status, published_at);

-- ---------- Contact / Leads ----------
CREATE TABLE contact_messages (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         TEXT NOT NULL,
  email        CITEXT NOT NULL,
  phone        TEXT,
  subject      TEXT,
  message      TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- Simple Audit trail ----------
CREATE TABLE audit_logs (
  id           BIGSERIAL PRIMARY KEY,
  user_id      UUID REFERENCES users(id) ON DELETE SET NULL,
  action       TEXT NOT NULL,        -- 'appointment.booked', 'membership.canceled', etc.
  entity_type  TEXT,
  entity_id    TEXT,
  meta         JSONB,                -- any extra context
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- =======================
-- Educational Hub content
-- =======================

CREATE TABLE education_articles (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title      TEXT NOT NULL,
  summary    TEXT,
  minutes    INT,                   -- e.g., 5 (min read)
  tags       TEXT[] DEFAULT '{}',   -- simple tags array
  cover_url  TEXT,                  -- image URL (e.g., /images/edu/iv-therapy.jpg)
  href       TEXT,                  -- external or internal link
  is_active  BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX education_articles_active_idx ON education_articles (is_active);
CREATE INDEX education_articles_title_trgm ON education_articles USING GIN (title gin_trgm_ops);

CREATE TABLE education_videos (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title      TEXT NOT NULL,
  duration   TEXT,                  -- e.g., '3:42'
  tags       TEXT[] DEFAULT '{}',
  thumb_url  TEXT,                  -- thumbnail image
  href       TEXT,                  -- YouTube/Vimeo/etc.
  is_active  BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX education_videos_active_idx ON education_videos (is_active);
CREATE INDEX education_videos_title_trgm ON education_videos USING GIN (title gin_trgm_ops);

CREATE TABLE education_downloads (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title      TEXT NOT NULL,
  file_size  TEXT,                  -- e.g., '120 KB'
  href       TEXT NOT NULL,         -- e.g., /downloads/pre-appointment-checklist.pdf
  is_active  BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX education_downloads_active_idx ON education_downloads (is_active);

CREATE INDEX audit_action_time_idx ON audit_logs (action, created_at);

-- ---------- Triggers to keep updated_at fresh ----------
CREATE OR REPLACE FUNCTION touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END; $$ LANGUAGE plpgsql;

CREATE TRIGGER t_users_upd        BEFORE UPDATE ON users        FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER t_profiles_upd     BEFORE UPDATE ON profiles     FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER t_products_upd     BEFORE UPDATE ON products     FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER t_appointments_upd BEFORE UPDATE ON appointments FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER t_posts_upd        BEFORE UPDATE ON blog_posts   FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
