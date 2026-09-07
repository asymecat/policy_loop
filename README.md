# PolicyLoop

**OpenHarmony SELinux 运行态策略自学习 + 最小权限收敛**

把内核记下的 `avc: denied` 访问拒绝日志,自动「读懂 → 定位根因 → 生成最小安全修复 → 评审验证 → 一键把设备从 permissive 收紧到 enforcing」。

> 2026 开源鸿蒙大学生创新大赛 · 赛道一「系统与技术创新」· 10/31 提交

---

## 它解决什么问题

OpenHarmony 里,应用/服务想碰系统资源都得过 **SELinux** 这道门禁;刷不过去,内核就记一条 `avc: denied`(访问被拒)日志。但这类日志开发者普遍**看不懂、也不知道该在哪补规则**,很多人干脆把门禁开成"只记不拦"(permissive)。

**一条 denial 长这样:**

```
avc:  denied { read } comm="media_service" path="/dev/video0"
     scontext=u:r:media_service:s0  tcontext=u:object_r:camera_device:s0
     tclass=chr_file permissive=1
```

- `scontext` = 发起方(哪个进程/权限域,如 `media_service`)
- `tcontext` = 目标(要碰哪类资源,如 `camera_device`)
- `tclass` = 资源种类(这里是字符设备 `chr_file`)
- 结尾 `permissive=1` 只记不拦;`permissive=0` 是真拦截、那功能就失败了

**被拒不一定是"缺规则",所以补丁不能乱补:**

- 规则写在 `.te` 文件里,形如 `allow media_service camera_device:chr_file { ioctl };` = 允许媒体服务对摄像头设备做 `ioctl`;
- 但 `file_contexts` 规定文件系统里"哪个文件贴什么标签"——**标签贴错了也会被拒**,根因≠缺规则。

PolicyLoop 要做的是把每条 denial 自动归到五类根因之一,然后分而治之:

> **缺规则** · **标签贴错** · **跑错权限域** · **疑似越权(报警)** · **噪音**

对前三类自动出最小安全修复、对越权报警、把噪音滤掉——**不需要人读懂日志,机器替你读、替你定位、替你出最小修复,还替你验证安全**。

## 交付的样子(演示主线)

1. 一台鸿蒙真机处于 permissive —— 跑一个真实场景,采集器抓到一堆 denial
2. PolicyLoop 在 PC 上把每条日志**解析成人话**
3. 多智能体(AI)定位根因,给出**最小权限修复补丁**草稿
4. 评审 agent 挑刺:不放太宽、不违反系统红线
5. 一键把设备**收紧到 enforcing** —— 系统功能依旧正常、越权访问被挡

## 两层架构

| 端 | 内容 | 谁开发 |
|---|---|---|
| **设备端(轻)** | 真机上抓 denial 日志的小采集器 | 队长(M3 用真机) |
| **主机端(重)** | PC 端分析平台(主要开发部分)—— **确定性内核**(解析/索引/诊断/验证,可证明可离线)+ **多智能体**(AI 定位与文案,可摘除) | 团队主力,纯 Python |

## 快速开始(队友 / 贡献者)

只需要 **Python 3.12**。⚠️ **不需要 OHOS 源码树、不需要真机、不需要 GPU** —— 那是 M3 队长侧(ohos_src + DAYU200)才碰的东西,按 onboarding 推进即可。

```bash
# 1. 独立 Python 环境
conda create -n pl python=3.12 -y
conda activate pl

# 2. 拉仓库
git clone https://github.com/asymecat/policy_loop.git
cd policy_loop

# 3. 自检:看到 "✔ 环境 OK" 就算通过
python -m policy_loop.selfcheck
```

## 项目结构

```
policy_loop/
├── docs/onboarding.md   # 队友上手手册:概念 → 分步任务 → 完成标志
├── README.md            # 你正在看的
└── policy_loop/         # 主包(纯 Python,零第三方依赖)
    ├── selfcheck.py     # 环境自检入口
    └── avc/             # avc 解析层:denial 文本 -> 结构化 JSON
        ├── parser.py    # 行解析
        ├── contexts.py  # scontext/tcontext/tclass 归一化
        ├── model.py     # 结构化数据模型
        └── tests/       # 用例 + 真实格式 fixture
```

## 文档导航

- 想**上手开发 / 了解每一步任务 / 查看进度里程碑(M0–M4)**:看 [`docs/onboarding.md`](docs/onboarding.md),进度只在 onboarding 维护,不在此重复
- 想**验证自己环境**:跑上面快速开始的第 3 步 `python -m policy_loop.selfcheck`
