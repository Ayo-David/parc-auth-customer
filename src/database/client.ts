import knex, { type Knex } from "knex";
import type { AppConfig } from "../config/env.js";

export function createDatabase(config: AppConfig): Knex {
  return knex({
    client: "pg",
    connection: config.DATABASE_URL,
    pool: {
      min: config.DATABASE_POOL_MIN,
      max: config.DATABASE_POOL_MAX,
      afterCreate(
        connection: unknown,
        done: (error: Error | null, connection: unknown) => void,
      ) {
        const client = connection as {
          query: (sql: string, callback: (error: Error | null) => void) => void;
        };
        client.query("SET application_name = 'parc-auth-customer'", (error) => {
          done(error, connection);
        });
      },
    },
  });
}

export async function checkDatabase(database: Knex): Promise<void> {
  await database.raw("SELECT 1");
}

export async function closeDatabase(database: Knex): Promise<void> {
  await database.destroy();
}
