export async function asyncMapLimit<T, U>(values: readonly T[], limit: number, fn: (value: T, index: number) => Promise<U>): Promise<U[]> {
  return Promise.all(values.map(fn));
}
