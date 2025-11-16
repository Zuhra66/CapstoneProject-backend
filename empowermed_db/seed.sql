-- =========================================================
-- EmpowerMed seed data (aligned with schema.sql)
-- Safe to re-run (idempotent)
-- =========================================================
BEGIN;

-- -------------------------
-- Categories
-- -------------------------
INSERT INTO categories (name, slug) VALUES
  ('Skincare','skincare'),
  ('Beverage','beverage'),
  ('Supplement','supplement')
ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name;

-- -------------------------
-- Tags
-- -------------------------
INSERT INTO tags (name) VALUES
  ('Hydration'),
  ('Radiance'),
  ('Complete Set'),
  ('Luxurious'),
  ('Antioxidants'),
  ('Plant-based'),
  ('Firming')
ON CONFLICT (name) DO NOTHING;

-- -------------------------
-- Products
-- NOTE: price_cents are integer cents (e.g., 380.00 -> 38000)
-- -------------------------
-- The Visage Collection
INSERT INTO products (name, slug, category_id, price_cents, image_url, external_url, is_active)
SELECT
  'The Visage Collection',
  'the-visage-collection',
  c.id,
  38000,
  '/images/visage-collection.jpg',
  'https://threeinternational.com/en/productdetail/1726492/3144/US',
  TRUE
FROM categories c WHERE c.slug = 'skincare'
ON CONFLICT (slug) DO UPDATE
SET
  category_id = EXCLUDED.category_id,
  price_cents = EXCLUDED.price_cents,
  image_url   = EXCLUDED.image_url,
  external_url= EXCLUDED.external_url,
  is_active   = EXCLUDED.is_active;

-- Visage Super Serum
INSERT INTO products (name, slug, category_id, price_cents, image_url, external_url, is_active)
SELECT
  'Visage Super Serum',
  'visage-super-serum',
  c.id,
  15900,
  '/images/visage-super-serum.jpg',
  'https://threeinternational.com/en/productdetail/1726492/3041/US',
  TRUE
FROM categories c WHERE c.slug = 'skincare'
ON CONFLICT (slug) DO UPDATE
SET
  category_id = EXCLUDED.category_id,
  price_cents = EXCLUDED.price_cents,
  image_url   = EXCLUDED.image_url,
  external_url= EXCLUDED.external_url,
  is_active   = EXCLUDED.is_active;

-- Visage Crème Caviar
INSERT INTO products (name, slug, category_id, price_cents, image_url, external_url, is_active)
SELECT
  'Visage Crème Caviar',
  'visage-creme-caviar',
  c.id,
  14000,
  '/images/visage-creme-caviar.jpg',
  'https://threeinternational.com/en/productdetail/1726492/3136/US',
  TRUE
FROM categories c WHERE c.slug = 'skincare'
ON CONFLICT (slug) DO UPDATE
SET
  category_id = EXCLUDED.category_id,
  price_cents = EXCLUDED.price_cents,
  image_url   = EXCLUDED.image_url,
  external_url= EXCLUDED.external_url,
  is_active   = EXCLUDED.is_active;

-- Éternel
INSERT INTO products (name, slug, category_id, price_cents, image_url, external_url, is_active)
SELECT
  'Éternel',
  'eternel',
  c.id,
  13000,
  '/images/eternel.jpg',
  'https://threeinternational.com/en/productdetail/1726492/2797/US',
  TRUE
FROM categories c WHERE c.slug = 'skincare'
ON CONFLICT (slug) DO UPDATE
SET
  category_id = EXCLUDED.category_id,
  price_cents = EXCLUDED.price_cents,
  image_url   = EXCLUDED.image_url,
  external_url= EXCLUDED.external_url,
  is_active   = EXCLUDED.is_active;

-- Vitalité
INSERT INTO products (name, slug, category_id, price_cents, image_url, external_url, is_active)
SELECT
  'Vitalité',
  'vitalite',
  c.id,
  8500,
  '/images/vitalite.jpg',
  'https://threeinternational.com/en/productdetail/1726492/2802/US',
  TRUE
FROM categories c WHERE c.slug = 'supplement'
ON CONFLICT (slug) DO UPDATE
SET
  category_id = EXCLUDED.category_id,
  price_cents = EXCLUDED.price_cents,
  image_url   = EXCLUDED.image_url,
  external_url= EXCLUDED.external_url,
  is_active   = EXCLUDED.is_active;

-- Kynetik Clean Caffeine
INSERT INTO products (name, slug, category_id, price_cents, image_url, external_url, is_active)
SELECT
  'Kynetik Clean Caffeine',
  'kynetik-clean-caffeine',
  c.id,
  8500,
  '/images/kynetik-clean-caffeine.jpg',
  'https://threeinternational.com/en/productdetail/1726492/3198/US',
  TRUE
FROM categories c WHERE c.slug = 'beverage'
ON CONFLICT (slug) DO UPDATE
SET
  category_id = EXCLUDED.category_id,
  price_cents = EXCLUDED.price_cents,
  image_url   = EXCLUDED.image_url,
  external_url= EXCLUDED.external_url,
  is_active   = EXCLUDED.is_active;

-- Pure Cleanse
INSERT INTO products (name, slug, category_id, price_cents, image_url, external_url, is_active)
SELECT
  'Pure Cleanse',
  'pure-cleanse',
  c.id,
  7500,
  '/images/pure-cleanse.jpg',
  'https://threeinternational.com/en/productdetail/1726492/3092/US',
  TRUE
FROM categories c WHERE c.slug = 'skincare'
ON CONFLICT (slug) DO UPDATE
SET
  category_id = EXCLUDED.category_id,
  price_cents = EXCLUDED.price_cents,
  image_url   = EXCLUDED.image_url,
  external_url= EXCLUDED.external_url,
  is_active   = EXCLUDED.is_active;

-- Revive
INSERT INTO products (name, slug, category_id, price_cents, image_url, external_url, is_active)
SELECT
  'Revive',
  'revive',
  c.id,
  7200,
  '/images/revive.jpg',
  'https://threeinternational.com/en/productdetail/1726492/2799/US',
  TRUE
FROM categories c WHERE c.slug = 'supplement'
ON CONFLICT (slug) DO UPDATE
SET
  category_id = EXCLUDED.category_id,
  price_cents = EXCLUDED.price_cents,
  image_url   = EXCLUDED.image_url,
  external_url= EXCLUDED.external_url,
  is_active   = EXCLUDED.is_active;

-- Purifi
INSERT INTO products (name, slug, category_id, price_cents, image_url, external_url, is_active)
SELECT
  'Purifi',
  'purifi',
  c.id,
  7000,
  '/images/purifi.jpg',
  'https://threeinternational.com/en/productdetail/1726492/2801/US',
  TRUE
FROM categories c WHERE c.slug = 'supplement'
ON CONFLICT (slug) DO UPDATE
SET
  category_id = EXCLUDED.category_id,
  price_cents = EXCLUDED.price_cents,
  image_url   = EXCLUDED.image_url,
  external_url= EXCLUDED.external_url,
  is_active   = EXCLUDED.is_active;

-- Collagène
INSERT INTO products (name, slug, category_id, price_cents, image_url, external_url, is_active)
SELECT
  'Collagène',
  'collagene',
  c.id,
  7000,
  '/images/collagene.jpg',
  'https://threeinternational.com/en/productdetail/1726492/2798/US',
  TRUE
FROM categories c WHERE c.slug = 'supplement'
ON CONFLICT (slug) DO UPDATE
SET
  category_id = EXCLUDED.category_id,
  price_cents = EXCLUDED.price_cents,
  image_url   = EXCLUDED.image_url,
  external_url= EXCLUDED.external_url,
  is_active   = EXCLUDED.is_active;

-- Imúne
INSERT INTO products (name, slug, category_id, price_cents, image_url, external_url, is_active)
SELECT
  'Imúne',
  'imune',
  c.id,
  7000,
  '/images/imune.jpg',
  'https://threeinternational.com/en/productdetail/1726492/2803/US',
  TRUE
FROM categories c WHERE c.slug = 'supplement'
ON CONFLICT (slug) DO UPDATE
SET
  category_id = EXCLUDED.category_id,
  price_cents = EXCLUDED.price_cents,
  image_url   = EXCLUDED.image_url,
  external_url= EXCLUDED.external_url,
  is_active   = EXCLUDED.is_active;

-- Radiant Toner
INSERT INTO products (name, slug, category_id, price_cents, image_url, external_url, is_active)
SELECT
  'Radiant Toner',
  'radiant-toner',
  c.id,
  5400,
  '/images/radiant-toner.jpg',
  'https://threeinternational.com/en/productdetail/1726492/3093/US',
  TRUE
FROM categories c WHERE c.slug = 'skincare'
ON CONFLICT (slug) DO UPDATE
SET
  category_id = EXCLUDED.category_id,
  price_cents = EXCLUDED.price_cents,
  image_url   = EXCLUDED.image_url,
  external_url= EXCLUDED.external_url,
  is_active   = EXCLUDED.is_active;

-- -------------------------
-- Product ↔ Tag mapping
-- -------------------------
-- Helper: attach tags to a product by slug
-- (Run ON CONFLICT DO NOTHING so it’s idempotent)

-- The Visage Collection → Hydration, Complete Set
INSERT INTO product_tags (product_id, tag_id)
SELECT p.id, t.id
FROM products p
JOIN tags t ON t.name IN ('Hydration','Complete Set')
WHERE p.slug = 'the-visage-collection'
ON CONFLICT DO NOTHING;

-- Visage Super Serum → Radiance, Firming
INSERT INTO product_tags (product_id, tag_id)
SELECT p.id, t.id
FROM products p
JOIN tags t ON t.name IN ('Radiance','Firming')
WHERE p.slug = 'visage-super-serum'
ON CONFLICT DO NOTHING;

-- Visage Crème Caviar → Luxurious
INSERT INTO product_tags (product_id, tag_id)
SELECT p.id, t.id
FROM products p
JOIN tags t ON t.name IN ('Luxurious')
WHERE p.slug = 'visage-creme-caviar'
ON CONFLICT DO NOTHING;

-- Éternel → Antioxidants
INSERT INTO product_tags (product_id, tag_id)
SELECT p.id, t.id
FROM products p
JOIN tags t ON t.name IN ('Antioxidants')
WHERE p.slug = 'eternel'
ON CONFLICT DO NOTHING;

-- Kynetik Clean Caffeine → Plant-based
INSERT INTO product_tags (product_id, tag_id)
SELECT p.id, t.id
FROM products p
JOIN tags t ON t.name IN ('Plant-based')
WHERE p.slug = 'kynetik-clean-caffeine'
ON CONFLICT DO NOTHING;

-- -------------------------
-- Services
-- -------------------------
INSERT INTO services (name, slug, description, duration_min, price_cents, is_active)
VALUES
  ('Consultation','consultation','Initial wellness consultation',30, 0, TRUE),
  ('IV Therapy','iv-therapy','Hydration IV therapy',60, 14900, TRUE)
ON CONFLICT (slug) DO UPDATE
SET description  = EXCLUDED.description,
    duration_min = EXCLUDED.duration_min,
    price_cents  = EXCLUDED.price_cents,
    is_active    = EXCLUDED.is_active;

-- -------------------------
-- Locations
-- -------------------------
INSERT INTO locations (name, address1, city, region, postal_code, country, tz)
VALUES
  ('EmpowerMed Clinic','123 Wellness Ave','Sacramento','CA','95814','USA','America/Los_Angeles')
ON CONFLICT (id) DO NOTHING;  -- table uses UUID PK; this is just a simple seed row

-- =======================
-- Seed: Educational Hub
-- =======================
INSERT INTO education_articles (title, summary, minutes, tags, cover_url, href, is_active)
VALUES
  ('What Is IV Hydration Therapy?',
   'A clinician’s guide to hydration IVs: indications, benefits, safety, and who should avoid it.',
   6, ARRAY['IV Therapy','Hydration','New to EmpowerMed'],
   '/images/edu/iv-therapy.jpg',
   '#', TRUE),
  ('Skincare Routines: Morning vs. Night',
   'Derm-backed steps for cleansers, serums, and moisturizers—what to use and when.',
   5, ARRAY['Skincare','Routines'],
   '/images/edu/skin-routine.jpg',
   '#', TRUE),
  ('Supplements 101: What to Look For',
   'Labels, dosing, and evidence: choosing supplements with confidence.',
   7, ARRAY['Supplements','Wellness'],
   '/images/edu/supplements.jpg',
   '#', TRUE)
ON CONFLICT DO NOTHING;

INSERT INTO education_videos (title, duration, tags, thumb_url, href, is_active)
VALUES
  ('Hydration IV: What to Expect', '3:42', ARRAY['IV Therapy'], '/images/edu/video-iv.jpg', 'https://www.youtube.com/watch?v=dQw4w9WgXcQ', TRUE),
  ('Serums Explained',              '2:58', ARRAY['Skincare'],  '/images/edu/video-serums.jpg', 'https://www.youtube.com/watch?v=dQw4w9WgXcQ', TRUE)
ON CONFLICT DO NOTHING;

INSERT INTO education_downloads (title, file_size, href, is_active)
VALUES
  ('Pre-Appointment Checklist (PDF)', '120 KB', '/downloads/pre-appointment-checklist.pdf', TRUE),
  ('IV Hydration After-Care (PDF)',   '98 KB',  '/downloads/iv-aftercare.pdf', TRUE)
ON CONFLICT DO NOTHING;


COMMIT;
