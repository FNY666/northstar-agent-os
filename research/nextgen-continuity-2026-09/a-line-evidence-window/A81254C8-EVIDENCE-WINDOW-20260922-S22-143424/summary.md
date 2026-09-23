# S22 summary

跨云 evidence-window 需要分离事件发生、采集、查询、保留、完整性和业务后置条件。`NO_EVENT` 是强结论，必须证明完整覆盖与完整查询；任何覆盖、权限、分页、延迟或保留未知都降级为 `QUERY_GAP`/`UNKNOWN`。