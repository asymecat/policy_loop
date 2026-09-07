鸿蒙系统里有个叫 SELinux 的门禁,凡是应用/服务想碰系统资源都得刷卡;卡刷不过去,系统会记一条「访问被拒日志」(denial)。这些日志开发者看不懂、也不知道该在哪补权限规则,很多人干脆把门禁关成"只记不拦"(permissive)
我们要做的就是把这些日志自动读懂 → 定位是哪儿的问题 → 给出最小、安全的修复规则,还能一键把设备从权限开放收紧到严格拦截。拆成两层:
设备端(轻)：一个小采集器,在鸿蒙真机上抓 denial 日志。
主机端(重,我们主要开发的部分):一个 PC 端分析平台,把日志变成修复方案,好看、可验证、能录屏演示。

被门禁拦下时,内核会写一条日志,大概长这样:

```
avc: denied { read } ... comm="media_service" path="/dev/video0"
     scontext=u:r:media_service:s0  tcontext=u:object_r:camera_device:s0
     tclass=chr_file permissive=1
```

- `scontext` = 哪个进程/权限域
- `tcontext` = 哪类资源
- 结尾 `permissive=1` 表示没有拦截;`permissive=0` 表示拦截了,功能会失败。
- `.te` 文件:写规则的地方,例如 `allow media_service camera_device:chr_file { ioctl };` 意思"允许媒体服务对摄像头设备做 ioctl"。
- `file_contexts` 等:规定"文件系统里某个文件贴什么标签。文件标签贴错了,也是被拒的原因之一(根因≠缺规则)。

---

交付的作品长什么样
对评委的最终 demo 大致是:

1. 一台鸿蒙真机处于 permissive状态;
2. 跑一个真实场景,采集器抓到一堆 denial;
3. PolicyLoop 在 PC 上把每条日志解析成人话,多智能体(AI)定位根因、给出最小权限修复补丁;
4. 评审检查补丁不会放得太宽、不违反系统红线;
5. 一键把设备收紧到严格拦截,系统功能依旧正常、越权访问被挡。

环境准备：
ohos_src 源码树、DAYU200真机、python环境

搭建环境的步骤：
```bash
 建独立 python 环境
conda create -n pl python=3.12 -y
conda activate pl

拉仓库
git clone https://github.com/asymecat/policy_loop.git ~/policy_loop
cd ~/policy_loop

自检:能跑通就算环境 OK
python -m policy_loop.selfcheck
```

把几个关键 `.te`、`file_contexts`、示例 denial解析
完成的标志:输入一条 denial,解析器输出结构化 JSON;索引器能回答"某进程现在有没有某权限"。

把 denial 自动分成几类 —— 缺规则 / 标签贴错 / 跑错权限域 / 疑似越权(报警) / 噪音
完成的标志：分类准确率 > 90%

在确定性骨架上加 AI 定位与文案:输入"案件档案",输出"根因 + 修复补丁草稿 + 人话解释"
加评审 agent挑刺:会不会放太宽/违反红线，补丁后,确认这条 denial 消失且无新越权
修复正确率达标、评审拒绝率(幻觉)压到很低。

在真机上抓denial日志
验证一次"标签贴错 → 改 label → 恢复"的真实修复

最后文档、PPT、演示视频、仓库整理;10/31 截止前提交

