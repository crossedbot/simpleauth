CREATE DATABASE "auth";

\c "auth"

CREATE TABLE "users" (
  "id"            bigserial,
  "created_at"    timestamptz,
  "updated_at"    timestamptz,
  "deleted_at"    timestamptz,
  "first_name"    text,
  "last_name"     text,
  "password"      text,
  "email"         text,
  "username"      text,
  "phone"         text,
  "user_type"     text,
  "user_id"       text,
  "token"         text,
  "refresh_token" text,
  "totp_enabled"  boolean,
  "totp"          text,
  "options"       text,
  "public_key"    text,
  PRIMARY KEY ("id")
)

