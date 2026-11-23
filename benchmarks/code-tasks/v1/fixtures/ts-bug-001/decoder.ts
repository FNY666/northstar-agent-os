export function decodeChunks(chunks: readonly Uint8Array[]): string {
  return chunks.map(chunk => new TextDecoder().decode(chunk)).join("");
}
