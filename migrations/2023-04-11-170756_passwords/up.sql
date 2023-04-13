-- Your SQL goes here
CREATE TABLE passwords (
  id VARCHAR DEFAULT uuid_generate_v4() PRIMARY KEY,
  name VARCHAR NOT NULL,
  username VARCHAR NOT NULL,
  value BYTEA NOT NULL,
  website VARCHAR,
  note VARCHAR,
  key BYTEA NOT NULL,
  nonce BYTEA NOT NULL,
  user_id VARCHAR REFERENCES users(id) NOT NULL,
  created_at VARCHAR DEFAULT NOW(),
  updated_at VARCHAR,
  UNIQUE (name, user_id)
)
