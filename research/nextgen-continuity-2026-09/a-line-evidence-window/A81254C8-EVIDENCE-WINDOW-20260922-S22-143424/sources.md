# S22 sources

访问日期：2026-09-22。

1. Google Cloud, Audit Logs — https://cloud.google.com/logging/docs/audit — primary；覆盖类别、记录和查询边界。
2. AWS, How CloudTrail works — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/how-cloudtrail-works.html — primary；交付、区域与事件历史边界。
3. Microsoft, Azure Activity Log — https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log — primary；订阅级活动日志、保留/导出边界。

证据窗口：上述官方页面只支持平台日志机制与边界；不能直接支持跨云业务效果、无损或 exactly-once。