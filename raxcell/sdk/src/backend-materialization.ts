import type { BackendFamily, WindowsRunnerBackend } from "./types.js";

export type WriteGrantMaterializationMode = "raxcell-precreate" | "runner-owned";

export function writeGrantMaterializationMode(
  backend: WindowsRunnerBackend,
): "runner-owned";
export function writeGrantMaterializationMode(
  backend: Exclude<BackendFamily, WindowsRunnerBackend> | null,
): "raxcell-precreate";
export function writeGrantMaterializationMode(
  backend: BackendFamily | null,
): WriteGrantMaterializationMode;
export function writeGrantMaterializationMode(
  backend: BackendFamily | null,
): WriteGrantMaterializationMode {
  if (
    backend === "windows-native" ||
    backend === "windows-elevated" ||
    backend === "windows-unelevated"
  ) {
    return "runner-owned";
  }
  return "raxcell-precreate";
}
