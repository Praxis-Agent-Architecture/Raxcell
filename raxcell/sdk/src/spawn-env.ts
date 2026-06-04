export type SpawnEnvMode = "inherit" | "clean";

export function buildPreparedSpawnEnv(
  requestEnv: Record<string, string> | undefined,
  mode: SpawnEnvMode,
  hostEnv: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv | undefined {
  if (mode === "clean") {
    return { ...(requestEnv ?? {}) };
  }
  return requestEnv ? { ...hostEnv, ...requestEnv } : undefined;
}
