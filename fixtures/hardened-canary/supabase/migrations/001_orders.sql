CREATE TABLE orders (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  quantity INTEGER NOT NULL CHECK (quantity > 0),
  total INTEGER NOT NULL CHECK (total > 0)
);

ALTER TABLE orders ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own orders"
  ON orders FOR SELECT
  USING (auth.uid()::text = user_id);
