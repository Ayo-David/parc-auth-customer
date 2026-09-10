export interface ReadinessCheck {
  name: string;
  check: () => Promise<void>;
}

export interface ReadinessResult {
  ready: boolean;
  checks: Record<string, "UP" | "DOWN">;
}

export async function checkReadiness(
  checks: readonly ReadinessCheck[],
): Promise<ReadinessResult> {
  const results = await Promise.all(
    checks.map(async ({ name, check }) => {
      try {
        await check();
        return [name, "UP"] as const;
      } catch {
        return [name, "DOWN"] as const;
      }
    }),
  );
  return {
    ready: results.every(([, status]) => status === "UP"),
    checks: Object.fromEntries(results),
  };
}
