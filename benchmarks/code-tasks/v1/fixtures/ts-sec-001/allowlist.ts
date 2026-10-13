export function isAllowedUrl(raw: string, origins: readonly string[]): boolean {
  return origins.some(origin => raw.startsWith(origin));
}
