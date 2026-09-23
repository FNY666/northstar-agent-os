# A-P0-TCONTRACT-REVIEW-3

身份：A。范围：树外、离线、无副作用的下一轮准入门槛审查；不触碰共享 P0 事故目录、140、canonical、tri-line、systemd、真实凭据。

## 目标

1. 把 T-Contract-0 的 `Conditional GO` 与真实接入前门槛拆开。
2. 对每一个生产可信根缺口给出阻断条件、可接受证据和不能替代它的证据。
3. 明确 D1 opt-in 的 fail-closed 顺序。

## A 线当前规则

- 纯 schema：可以验证结构、规范化、重复键、字段绑定、状态投影、fixture 内重放规则。
- 生产 authority：必须是独立、可验证、可撤销/过期的权威，不接受 validator 内置测试密钥。
- producer：必须有认证身份、授权 scope、目标绑定和审计关联；字符串字段或 producer 自报不构成身份。
- registry：必须是持久、原子、可审计的 registry/CAS；进程内 dict 只证明当前进程的演练。
- readback：必须从独立权威通道读取目标状态；receipt、trace、日志、producer 声明不能替代 readback。
- fencing：必须在目标提交面拒绝旧 owner/token；仅有锁、lease、heartbeat、attempt number 不足。
- time：必须绑定可信时钟/expiry/replay 规则；调用方传入 `now` 不是可信时间证明。
- secret：凭据只能通过受控 secret boundary 使用；不能进入 schema、fixture、日志、异常、Baggage 或不可信 producer payload。

## D1 前门槛

默认不得执行真实动作；显式 opt-in 只是必要条件，不是充分授权。只有在 authority、target allowlist/fingerprint、producer auth、registry/CAS、fencing、trusted time、独立 readback、secret boundary、append-only audit 和回滚/reconcile 全部闭合时，才允许进入真实 dry-run；任何缺口必须拒绝或保持 unknown，不得升级为 verified。

## 本轮状态

继续执行独立离线核验与证据矩阵；阶段报告完成后补充 wc、sha256、测试输出和证据等级。
