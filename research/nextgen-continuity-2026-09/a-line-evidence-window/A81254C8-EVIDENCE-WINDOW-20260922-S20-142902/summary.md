# S20 summary

结论：跨系统连续性验收必须把生产、导出、查询、保留、完整性和外部后置条件分轴；8种状态不能由单一平台回执推导。尤其是空结果：只有在查询完整、保留期有效、无权限/分页/版本缺口且独立健康检查通过时才允许 `NO_EVENT`；否则是 `QUERY_GAP` 或 `UNKNOWN`。`VERIFIED_CONTINUITY` 需要独立 postcondition/read-back。

- verified：三份官方资料的机制边界及本目录验收脚本输出。
- inferred：统一 schema、状态互斥谓词和跨系统映射。
- unknown：真实系统的生产覆盖、采样、丢失检测和外部效果。
