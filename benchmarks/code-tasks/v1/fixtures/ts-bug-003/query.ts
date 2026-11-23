export function buildQuery(params: Record<string, string | readonly string[] | undefined>): string {
  return Object.entries(params).map(([key, value]) => key + "=" + String(value)).join("&");
}
