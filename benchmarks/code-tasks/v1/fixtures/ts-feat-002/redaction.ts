export function redact<T>(value: T, paths: readonly string[], replacement: unknown = "***"): T {
  const result = {...(value as Record<string, unknown>)};
  for (const path of paths) if (path in result) result[path] = replacement;
  return result as T;
}
