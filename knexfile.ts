import type { Knex } from "knex";

const connection =
  process.env.DATABASE_URL ?? "postgresql:///parc_auth_customer";

const config: Knex.Config = {
  client: "pg",
  connection,
  pool: { min: 0, max: 10 },
  migrations: {
    directory: "./db/migrations",
    extension: "ts",
    tableName: "knex_migrations",
  },
};

export default config;
