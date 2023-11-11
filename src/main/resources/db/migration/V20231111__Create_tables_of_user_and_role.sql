-- Create user table
CREATE TABLE "public"."user"
(
    "id"              SERIAL,
    "name"            TEXT    NOT NULL,
    "login"           TEXT    NOT NULL,
    "password"        TEXT    NOT NULL,
    "expiration_date" DATE    NOT NULL,
    "active"          BOOLEAN NOT NULL DEFAULT 'true',
    "created"         TIMESTAMP WITHOUT TIME ZONE,
    CONSTRAINT "user_pk" PRIMARY KEY ("id")
);

-- Create role table
create TABLE "role" (
    "id" SERIAL,
    "role" TEXT NOT NULL UNIQUE,
    CONSTRAINT "role_pk" PRIMARY KEY ("id")
);

-- Create user_roles table
CREATE TABLE "user_roles"
(
    "id"      SERIAL,
    "fk_user" INTEGER NOT NULL,
    "fk_role" INTEGER NOT NULL,
    CONSTRAINT "user_roles_pk" PRIMARY KEY ("id")
);

-- Includes foreign keys
ALTER TABLE "user_roles" ADD CONSTRAINT "fk_user" FOREIGN KEY ("fk_user") REFERENCES "public"."user" ("id");
ALTER TABLE "user_roles" ADD CONSTRAINT "fk_role" FOREIGN KEY ("fk_role") REFERENCES "public"."role" ("id");

-- Includes unique user_role
ALTER TABLE "public"."user_roles" ADD UNIQUE ("fk_user", "fk_role");
