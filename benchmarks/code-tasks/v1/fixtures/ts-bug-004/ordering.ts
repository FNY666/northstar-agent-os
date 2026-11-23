export interface RecordItem {id: string; priority: number}
export function sortByPriority(items: readonly RecordItem[]): RecordItem[] {
  return [...items].sort((a, b) => a.priority === b.priority ? -1 : b.priority - a.priority);
}
