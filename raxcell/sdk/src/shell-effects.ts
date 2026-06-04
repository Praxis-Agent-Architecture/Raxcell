import { isAbsolute, normalize, resolve } from "node:path";

export type ShellEffectAccess = "read" | "write" | "readwrite";

export type ShellEffect = {
  path?: string;
  pattern?: string;
  rawToken: string;
  access: ShellEffectAccess;
  command: string;
  reason: string;
  confidence: "high" | "medium" | "low";
  warning?: string;
};

type Token = {
  text: string;
  quote: "single" | "double" | null;
};

type CommandSegment = {
  tokens: Token[];
  redirects: Array<{ op: string; target?: Token }>;
};

const SHELL_NAMES = new Set(["sh", "bash", "dash", "zsh", "fish"]);
const READ_COMMANDS = new Set(["cat", "grep", "head", "tail", "less", "more", "awk"]);
const WRITE_COMMANDS = new Set(["touch", "mkdir", "rm", "rmdir", "chmod", "chown", "chgrp"]);

export function analyzeShellEffects(argv: string[], cwd: string): ShellEffect[] {
  const shellScript = shellScriptFromArgv(argv);
  if (shellScript !== null) {
    return analyzeShellScript(shellScript, cwd);
  }
  return analyzeCommandTokens(argv.map((text) => ({ text, quote: null })), cwd, argv[0] ?? "");
}

export function analyzeShellScript(script: string, cwd: string): ShellEffect[] {
  const segments = splitCommands(tokenizeShell(script));
  return segments.flatMap((segment) => analyzeSegment(segment, cwd));
}

function shellScriptFromArgv(argv: string[]): string | null {
  if (argv.length < 3) {
    return null;
  }
  const executable = basename(argv[0]);
  if (!SHELL_NAMES.has(executable)) {
    return null;
  }
  const optionIndex = argv.findIndex((arg, index) => index > 0 && (arg === "-c" || arg === "-lc" || arg === "-cl"));
  return optionIndex >= 0 ? argv[optionIndex + 1] ?? "" : null;
}

function analyzeSegment(segment: CommandSegment, cwd: string): ShellEffect[] {
  const effects: ShellEffect[] = [];
  const tokens = segment.tokens;
  const command = basename(tokens[0]?.text ?? "");

  for (const redirect of segment.redirects) {
    if (!redirect.target) {
      continue;
    }
    const access = redirect.op.includes(">") || redirect.op.includes("<>") ? "write" : "read";
    effects.push(effectFromToken(redirect.target, access, command, "shell-redirection", cwd));
  }

  if (tokens.length === 0) {
    return effects;
  }

  effects.push(...analyzeCommandTokens(tokens.map(stripAssignmentPrefix), cwd, command));
  return effects;
}

function analyzeCommandTokens(tokens: Token[], cwd: string, commandHint: string): ShellEffect[] {
  const effects: ShellEffect[] = [];
  const command = basename(tokens[0]?.text ?? commandHint);
  const args = tokens.slice(1);

  if (command === "cp" || command === "install" || command === "rsync") {
    const operands = nonOptionArgs(args);
    if (operands.length >= 2) {
      for (const source of operands.slice(0, -1)) {
        effects.push(effectFromToken(source, "read", command, `${command}-source`, cwd));
      }
      effects.push(effectFromToken(operands[operands.length - 1], "write", command, `${command}-destination`, cwd));
    }
  } else if (command === "mv") {
    const operands = nonOptionArgs(args);
    if (operands.length >= 2) {
      for (const source of operands.slice(0, -1)) {
        effects.push(effectFromToken(source, "readwrite", command, "mv-source", cwd));
      }
      effects.push(effectFromToken(operands[operands.length - 1], "write", command, "mv-destination", cwd));
    }
  } else if (WRITE_COMMANDS.has(command)) {
    for (const arg of nonOptionArgs(args)) {
      effects.push(effectFromToken(arg, "write", command, `${command}-target`, cwd));
    }
  } else if (command === "sed") {
    const inPlace = args.some((arg) => arg.text === "-i" || arg.text.startsWith("-i"));
    for (const arg of likelyFileArgs(args, { skipNextAfter: ["-e", "-f"] })) {
      effects.push(effectFromToken(arg, inPlace ? "readwrite" : "read", command, inPlace ? "sed-in-place" : "sed-read", cwd));
    }
  } else if (command === "perl") {
    const inPlace = args.some((arg) => arg.text.includes("i") && arg.text.startsWith("-"));
    for (const arg of likelyFileArgs(args, { skipNextAfter: ["-e"] })) {
      effects.push(effectFromToken(arg, inPlace ? "readwrite" : "read", command, inPlace ? "perl-in-place" : "perl-read", cwd));
    }
  } else if (command === "tee") {
    for (const arg of nonOptionArgs(args)) {
      effects.push(effectFromToken(arg, "write", command, "tee-output", cwd));
    }
  } else if (READ_COMMANDS.has(command)) {
    for (const arg of likelyFileArgs(args, { skipNextAfter: ["-e", "-f"] })) {
      effects.push(effectFromToken(arg, "read", command, `${command}-input`, cwd));
    }
  } else if (command === "python" || command === "python3" || command === "node") {
    const code = inlineCode(args);
    if (code) {
      effects.push(...analyzeInlineCode(code, cwd, command));
    }
  }

  for (const token of tokens) {
    if (isDynamicPathToken(token.text) && token.text.includes("/")) {
      effects.push(effectFromToken(token, "read", command || "unknown", "dynamic-path-token", cwd));
    }
  }
  return dedupeEffects(effects);
}

function analyzeInlineCode(code: string, cwd: string, command: string): ShellEffect[] {
  const effects: ShellEffect[] = [];
  if (command.startsWith("python")) {
    for (const match of code.matchAll(/open\(\s*(['"])(.*?)\1\s*(?:,\s*(['"])(.*?)\3)?/g)) {
      const mode = match[4] ?? "r";
      effects.push(effectFromRaw(match[2], pythonModeAccess(mode), command, "python-open", cwd));
    }
    for (const match of code.matchAll(/Path\(\s*(['"])(.*?)\1\s*\)\.write_(?:text|bytes)\s*\(/g)) {
      effects.push(effectFromRaw(match[2], "write", command, "python-pathlib-write", cwd));
    }
    for (const match of code.matchAll(/Path\(\s*(['"])(.*?)\1\s*\)\.read_(?:text|bytes)\s*\(/g)) {
      effects.push(effectFromRaw(match[2], "read", command, "python-pathlib-read", cwd));
    }
  }
  if (command === "node") {
    for (const match of code.matchAll(/\b(?:readFileSync|writeFileSync|appendFileSync)\s*\(\s*(['"])(.*?)\1/g)) {
      const fn = match[0].split("(")[0];
      const access = fn.includes("read") ? "read" : "write";
      effects.push(effectFromRaw(match[2], access, command, `node-fs-${fn}`, cwd));
    }
  }
  return effects;
}

function pythonModeAccess(mode: string): ShellEffectAccess {
  return /[wax+]/.test(mode) ? (mode.includes("+") ? "readwrite" : "write") : "read";
}

function tokenizeShell(script: string): Token[] {
  const tokens: Token[] = [];
  let current = "";
  let quote: Token["quote"] = null;
  let tokenQuote: Token["quote"] = null;
  for (let index = 0; index < script.length; index += 1) {
    const char = script[index];
    if (quote === "single") {
      if (char === "'") {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }
    if (quote === "double") {
      if (char === "\"") {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }
    if (char === "'") {
      quote = "single";
      tokenQuote ??= "single";
      continue;
    }
    if (char === "\"") {
      quote = "double";
      tokenQuote ??= "double";
      continue;
    }
    if (/\s/.test(char)) {
      pushToken();
      continue;
    }
    if ("|;&()".includes(char)) {
      pushToken();
      tokens.push({ text: char, quote: null });
      continue;
    }
    if (char === ">" || char === "<") {
      pushToken();
      let op = char;
      if (script[index + 1] === char || script[index + 1] === ">") {
        op += script[index + 1];
        index += 1;
      }
      tokens.push({ text: op, quote: null });
      continue;
    }
    current += char;
  }
  pushToken();
  return tokens;

  function pushToken(): void {
    if (current.length > 0) {
      tokens.push({ text: current, quote: tokenQuote });
      current = "";
      tokenQuote = null;
    }
  }
}

function splitCommands(tokens: Token[]): CommandSegment[] {
  const segments: CommandSegment[] = [];
  let current: CommandSegment = { tokens: [], redirects: [] };
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (["|", ";", "&", "(", ")"].includes(token.text)) {
      pushCurrent();
      continue;
    }
    if (/^\d*(?:>>?|<>|<<?)$/.test(token.text)) {
      current.redirects.push({ op: token.text, target: tokens[index + 1] });
      index += 1;
      continue;
    }
    current.tokens.push(token);
  }
  pushCurrent();
  return segments;

  function pushCurrent(): void {
    if (current.tokens.length > 0 || current.redirects.length > 0) {
      segments.push(current);
      current = { tokens: [], redirects: [] };
    }
  }
}

function effectFromRaw(
  rawToken: string,
  access: ShellEffectAccess,
  command: string,
  reason: string,
  cwd: string,
): ShellEffect {
  return effectFromToken({ text: rawToken, quote: null }, access, command, reason, cwd);
}

function effectFromToken(
  token: Token,
  access: ShellEffectAccess,
  command: string,
  reason: string,
  cwd: string,
): ShellEffect {
  if (isDynamicPathToken(token.text)) {
    return {
      rawToken: token.text,
      access,
      command,
      reason,
      confidence: "medium",
      warning: "shell-dynamic-path-unresolved",
    };
  }
  if (hasGlob(token.text)) {
    return {
      pattern: normalizeConcretePath(token.text, cwd),
      rawToken: token.text,
      access,
      command,
      reason,
      confidence: "medium",
      warning: "shell-glob-pattern",
    };
  }
  return {
    path: normalizeConcretePath(token.text, cwd),
    rawToken: token.text,
    access,
    command,
    reason,
    confidence: "high",
  };
}

function normalizeConcretePath(path: string, cwd: string): string {
  return normalize(isAbsolute(path) ? path : resolve(cwd, path));
}

function nonOptionArgs(args: Token[]): Token[] {
  return args.filter((arg) => !arg.text.startsWith("-"));
}

function likelyFileArgs(args: Token[], options: { skipNextAfter: string[] }): Token[] {
  const output: Token[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (options.skipNextAfter.includes(arg.text)) {
      index += 1;
      continue;
    }
    if (arg.text.startsWith("-")) {
      continue;
    }
    if (arg.text.includes("/") || isDynamicPathToken(arg.text) || hasGlob(arg.text)) {
      output.push(arg);
    }
  }
  return output;
}

function inlineCode(args: Token[]): string | null {
  for (let index = 0; index < args.length - 1; index += 1) {
    if (args[index].text === "-c" || args[index].text === "-e") {
      return args[index + 1].text;
    }
  }
  return null;
}

function stripAssignmentPrefix(token: Token): Token {
  if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token.text)) {
    return { ...token, text: token.text.replace(/^[A-Za-z_][A-Za-z0-9_]*=/, "") };
  }
  return token;
}

function isDynamicPathToken(token: string): boolean {
  return token.startsWith("~") || token.includes("$") || token.includes("`");
}

function hasGlob(token: string): boolean {
  return /[*?\[]/.test(token);
}

function basename(path: string): string {
  return path.split("/").filter(Boolean).pop() ?? path;
}

function dedupeEffects(effects: ShellEffect[]): ShellEffect[] {
  const seen = new Set<string>();
  return effects.filter((effect) => {
    const key = `${effect.path ?? effect.pattern ?? effect.rawToken}:${effect.access}:${effect.reason}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}
