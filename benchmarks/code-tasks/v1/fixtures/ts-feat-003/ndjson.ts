export async function* parseNdjson(chunks: AsyncIterable<string>): AsyncGenerator<unknown> {
  for await (const chunk of chunks) {
    for (const line of chunk.split("\n")) {
      if (line.trim()) yield JSON.parse(line);
    }
  }
}
