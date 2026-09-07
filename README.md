# PolicyLoop

OpenHarmony SELinux 运行态策略自学习 + 最小权限收敛 —— 把 `avc: denied` 日志自动读懂、
定位根因(缺规则 / 标签错 / 跑错域 / 越权 / 噪音)、生成最小安全修复,一键把设备从
permissive 收紧到 enforcing。

> 2026 开源鸿蒙大学生创新大赛 · 赛道一「系统与技术创新」

## 结构

```
policy_loop/
├── docs/onboarding.md    # 队友入门与搭建指南
└── policy_loop/
    ├── avc/              # avc 日志解析层(denial -> 结构化 JSON)
    └── ...               # (路线图)allow 索引器 / 诊断树 / 多智能体 / 黄金集
```

## 自检

```bash
python3 -m policy_loop.avc.tests.test_parser   # avc 解析器用例,全绿即环境 OK
```

## 路线图(M0 起,倒排至 10/31)

- [x] M0 地基之一:avc 解析器(解析成功 + 关键字段零分歧)
- [ ] M0 骨架 + 黄金集 + allow 集索引器
- [ ] M1 确定性诊断决策树(分类 >90%)
- [ ] M2 多智能体 + 评审/验证闭环
- [ ] M3 真机批次
- [ ] M4 文档 / PPT / 视频 / 提交(10/31)
