export interface ClientOptions {
  timeoutMs?: number;
}

export interface ResolvedClientOptions {
  timeoutMs: number;
}

export function resolveOptions(input: ClientOptions = {}): ResolvedClientOptions {
  return {timeoutMs: input.timeoutMs || 5_000};
}
