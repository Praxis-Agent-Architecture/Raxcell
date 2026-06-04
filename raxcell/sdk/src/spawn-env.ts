export type SpawnEnvMode = "inherit" | "clean";

export const DEFAULT_COMMAND_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

export function buildPreparedSpawnEnv(
  requestEnv: Record<string, string> | undefined,
  mode: SpawnEnvMode,
  hostEnv: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv | undefined {
  if (mode === "clean") {
    return buildSandboxCommandEnv(requestEnv);
  }
  return requestEnv ? { ...hostEnv, ...requestEnv } : undefined;
}

export function buildSandboxCommandEnv(
  requestEnv: Record<string, string> | undefined,
): Record<string, string> {
  return {
    PATH: DEFAULT_COMMAND_PATH,
    ...(requestEnv ?? {}),
  };
}
