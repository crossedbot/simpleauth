CREATE DATABASE "auth";

\c "auth"

CREATE TABLE "users" (
  "id"            bigserial,
  "first_name"    text,
  "last_name"     text,
  "password"      text,
  "email"         text,
  "username"      text,
  "phone"         text,
  "user_type"     text,
  "created_at"    timestamptz,
  "updated_at"    timestamptz,
  "user_id"       text,
  "token"         text,
  "refresh_token" text,
  "totp_enabled"  boolean,
  "totp"          text,
  "options"       text,
  PRIMARY KEY ("id")
)
