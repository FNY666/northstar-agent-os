# S36 sources

本切片为全离线 synthetic meta-test；未访问网络、真实 Gemini CLI/服务、凭据、shared/P0、事故目录、D10/L12/D14、canonical/staging/140/tri-line/systemd。没有外部事实来源，因此本报告结论均为本地运行推断（inferred），而非生产验证。

唯一输入证据为本目录内可审计文件：`fixtures/cases.json`、`impl_a.py`、`impl_b_baseline.py`、`impl_b_mut.py`、`harness.py`、`validator.py`。`canonical_input_sha256` 对每个 fixture 的 canonical JSON 输入进行 SHA-256 固化。
