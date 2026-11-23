export async function request(fetcher: () => Promise<{status: number; body: string}>): Promise<string> {
  let response;
  try { response = await fetcher(); }
  catch (error) { throw new Error("request failed: " + (error instanceof Error ? error.message : String(error))); }
  if (response.status >= 400) throw new Error("HTTP " + response.status);
  return response.body;
}
