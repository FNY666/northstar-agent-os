export function deepMerge(base: Record<string, unknown>, patch: Record<string, unknown>): Record<string, unknown> {
  const output = {...base};
  for (const [key, value] of Object.entries(patch)) {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      output[key] = deepMerge((output[key] || {}) as Record<string, unknown>, value as Record<string, unknown>);
    } else { output[key] = value; }
  }
  return output;
}
