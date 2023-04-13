-- Your SQL goes here
CREATE TABLE users (
  id VARCHAR DEFAULT uuid_generate_v4() PRIMARY KEY,
  username VARCHAR NOT NULL,
  email VARCHAR NOT NULL UNIQUE,
  CONSTRAINT email_pattern CHECK (email ~ '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}$'),
  password VARCHAR NOT NULL
)
