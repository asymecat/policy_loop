/**
 * PolicyLoop 控制台首页 —— 实时形态。
 *
 * 场景：开发者在改系统、刷版本、调服务，denial 正在往内核环里掉。
 * 打开这个开关之后，每读到一条**没见过的** denial，就弹出来告诉你
 * 「谁在访问谁、属于哪一类、最小修复是哪一行」。
 *
 * 架构是刻意不对称的，这不是妥协：
 *
 *   特权半边（板端守护 pl_guard.sh，以 root 常驻）
 *       读 /dev/kmsg ──▶ denial_check --follow ──▶ live.jsonl
 *   无特权半边（本应用，hap_domain）
 *       读 live.jsonl ──▶ libplnative 分类+出补丁 ──▶ 弹窗
 *
 * 为什么应用不能自己读 /dev/kmsg（三条都是策略划的线，不是没做）：
 *   1. 三档 HAP 全被 neverallow 挡在 /dev/kmsg 外；
 *   2. 没有任何 hap 类型有 `kernel:system syslog_read`；
 *   3. /dev/kmsg 是 0660 root:system —— DAC 先挡一道，板上还开着 dmesg_restrict=1。
 * 所以应用**一行提权代码都没有**，它只是显示器。要它变成传感器，
 * 就得给 hap_domain 开 syslog_read，那等于把整条审计流交给每个三方应用。
 *
 * 两个半边怎么交换数据：**不新开任何 SELinux 通道**，走应用自己的沙箱。
 *   沙箱标签是 debug_hap_data_file，板子策略里有
 *   `(allow hap_domain debug_hap_data_file (file (read write open)))`
 *   —— 应用读写自己的文件本来就允许。守护以 root 往同一目录写，文件按父目录
 *   继承同一个标签。于是两边都够得着，**一条新策略都不用加**。
 *   开关同理：应用只写自己沙箱里的 guard.on，守护轮询它。
 *
 * 引擎（pl_avc_parser / pl_index / pl_converge）已经编进 libplnative.so，
 * 索引随包发布。判定全在板子上做，**拔掉 USB 整条链路照常转**。
 */
import plnative from 'libplnative.so';
import buffer from '@ohos.buffer';
import common from '@ohos.app.ability.common';
import fs from '@ohos.file.fs';
import notificationManager from '@ohos.notificationManager';
import hilog from '@ohos.hilog';

const DOMAIN: number = 0x0000;
const TAG: string = 'PL_CONSOLE';

/** 随包发布的索引；以及一份板子上抓好的快照，用于「采集器没起」时对照。 */
const INDEX_RAW: string = 'ohos-5.0.3.pli';
const SNAPSHOT_RAW: string = 'board_denials.txt';

/** 列表里最多列几条。实时会话里去重之后案例本来就少，给足即可。 */
const MAX_FINDINGS: number = 40;

/** 一次轮询最多弹几条，防止策略集中放权时刷屏。 */
const NOTIFY_CAP: number = 3;

/** 轮询间隔。1s 是"实时"与"板子不发热"之间的折中。 */
const POLL_MS: number = 1000;

/** 守护写进来的文件名（两侧的约定，改一处要改两处）。 */
const LIVE_FILE: string = 'live.jsonl';
const SWITCH_FILE: string = 'guard.on';
/**
 * 现读快照的两个文件。
 *
 * 两个都**不是应用建的**：应用在自己的沙箱目录里没有 create 权限
 * （策略里 hap_domain 对 debug_hap_data_file 只有 read/write/open），
 * 所以它们由采集器预建 + chmod 0666，应用只改写已存在的那个。
 */
const REQ_FILE: string = 'snapshot.req';
const SNAP_FILE: string = 'snapshot.jsonl';

/** 一条判定结果，字段与原生侧 analyze 的 JSON 一一对应。 */
interface Finding {
  origin: string;   // board | tool —— 板子自带 vs 我们的工具造成的
  src: string;      // 源域，如 render_service
  tgt: string;      // 目标，如 dev_mali:chr_file
  op: string;       // 操作，如 ioctl 0x8014   ×72
  cls: string;      // 分类，如 XPERM_GAP
  fix: string;      // 最小修复规则
  verdict: string;  // 评审/验证结论
}

interface IndexInfo {
  ok: boolean;
  error: string;
  rev: string;
  rules: number;
  source: string;
}

interface AnalyzeResp {
  ok: boolean;
  error: string;
  total: number;
  unique: number;
  board: number;
  tool: number;
  findings: Finding[];
}

/** 采集器写的一行 JSONL。只要 raw 用来喂引擎，其余字段用来解释来源。 */
interface RawRec {
  fp: string;
  raw: string;
  comm: string | null;
  pid: number | null;
  permissive: boolean | null;
  src: string | null;
  tgt: string | null;
}

/** rawfile 是字节，引擎要的是 UTF-8 文本。 */
function toUtf8(bytes: Uint8Array): string {
  // slice 到精确范围：Uint8Array 可能是更大 buffer 上的视图，直接取 .buffer 会多带尾巴。
  const exact = (bytes.buffer as ArrayBuffer).slice(
    bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  return buffer.from(exact).toString('utf8');
}

/** 一条案例的身份。用它判断"这条我见过没有"。 */
function caseKey(f: Finding): string {
  return f.src + '|' + f.tgt + '|' + f.op + '|' + f.cls;
}

/**
 * `origin` 是引擎给的英文原值（'board' | 'tool'），界面上必须换成中文。
 *
 * 原先横幅那处忘了换，直接把原值拼进去 —— 工具造成的案例显示成
 * 「（板子自带 tool）」，正好把"板子自带 / 工具造成"这个区分说反。
 * 现在横幅和列表都走这里，改口径只改一处。
 */
function originLabel(origin: string): string {
  return origin === 'board' ? '板子自带' : '工具造成';
}

/** 等一小会儿。现读快照要轮询采集器写回的完成信号，而 ArkTS 里没有同步睡眠。 */
function sleep(ms: number): Promise<void> {
  return new Promise<void>((resolve: () => void) => {
    setTimeout(() => {
      resolve();
    }, ms);
  });
}

@Entry
@Component
struct Index {
  @State guardOn: boolean = false;
  @State status: string = '正在加载索引…';
  @State indexName: string = '-';
  @State summary: string = '';
  @State findings: Finding[] = [];
  @State err: string = '';
  @State busy: boolean = false;
  // 必须是 @State：开关和按钮的 enabled 都看它，用普通字段的话 bootstrap()
  // 里置 true 不会触发重渲染，控件会一直停在初始渲染的 enabled(false) 上，
  // 点了没反应。
  @State indexReady: boolean = false;

  /** 实时会话状态。 */
  @State liveLines: number = 0;     // 采集器一共写了多少行（去重后）
  @State newCount: number = 0;      // 本次会话新发现的案例数
  /**
   * 「载入当前快照 / 回放预录样本」这条动线自己的状态。
   *
   * 不复用 err 与 status：那两个字段 tick() 每成功一轮都会覆盖，按钮的报错
   * 写在那里只显示得到 1 秒。snapMode 为真时 tick() 整个不跑（视图冻结），
   * 解冻的唯一入口是拨开关。
   */
  @State snapMode: boolean = false;
  @State snapMsg: string = '';
  @State snapMsgBad: boolean = false;
  /** 最新一条的弹窗内容——应用内那份，通知被系统关掉时它是唯一可见的。 */
  @State popTitle: string = '';
  @State popBody: string = '';
  @State popFix: string = '';
  @State sandbox: string = '';

  private filesDir: string = '';
  private snapshotText: string = '';
  private timerId: number = -1;
  private pollBusy: boolean = false;
  private seen: Set<string> = new Set();
  private notifyId: number = 1;
  private notifyAsked: boolean = false;

  aboutToAppear(): void {
    this.bootstrap();
  }

  aboutToDisappear(): void {
    if (this.timerId >= 0) {
      clearInterval(this.timerId);
      this.timerId = -1;
    }
  }

  /** 读 rawfile、把索引交给原生侧解析一次，之后每轮分析复用。 */
  async bootstrap(): Promise<void> {
    try {
      const ctx = getContext(this) as common.UIAbilityContext;
      const rm = ctx.resourceManager;

      // 沙箱路径显示出来：现场排障时第一件要确认的事就是
      // "应用以为的目录"和"守护写进去的目录"是不是同一个。
      this.filesDir = ctx.filesDir;
      this.sandbox = this.filesDir;
      hilog.info(DOMAIN, TAG, 'filesDir=%{public}s', this.filesDir);

      // ★ 开关是**落在沙箱文件里**的，跨进程重启后仍然在，所以启动时必须读回来。
      // 不读的话界面显示「关」而采集器其实在采（它是按文件判的，不看界面）：
      // 演示者这时一拨，写进去的还是 '1'，没有 0→1 的跳变，守护不开新会话，
      // 探针也就不触发 —— 现场表现为「拨了没反应」，且极像工具坏了。
      // 放在第一个 await 之前，所以它是同步完成的，首帧渲染时值就是对的。
      this.guardOn = this.readSwitch();

      const idxBytes = await rm.getRawFileContent(INDEX_RAW);
      hilog.info(DOMAIN, TAG, 'index rawfile: %{public}d bytes', idxBytes.byteLength);
      const info = JSON.parse(await plnative.loadIndex(toUtf8(idxBytes))) as IndexInfo;
      if (!info.ok) {
        this.err = '索引加载失败：' + info.error;
        this.status = '索引不可用';
        return;
      }
      this.indexReady = true;
      this.indexName = info.rev.substring(0, 8) + ' · ' + info.rules + ' 条规则';

      const snapBytes = await rm.getRawFileContent(SNAPSHOT_RAW);
      this.snapshotText = toUtf8(snapBytes);
      this.status = this.guardOn ? '监听中 · 等待 denial…' : '就绪 · 开关关闭';
      hilog.info(DOMAIN, TAG, 'ready: %{public}s', this.indexName);

      // 轮询常开：开关关着时 tick 直接返回，不做任何 I/O。
      this.timerId = setInterval(() => {
        this.tick();
      }, POLL_MS);
    } catch (e) {
      this.err = '初始化失败：' + (e as Error).message;
      this.status = '初始化失败';
      hilog.error(DOMAIN, TAG, 'bootstrap failed: %{public}s', (e as Error).message);
    }
  }

  /** 把开关落到沙箱里；守护轮询这个文件。 */
  private writeSwitch(on: boolean): void {
    const path = this.filesDir + '/' + SWITCH_FILE;
    const f = fs.openSync(path, fs.OpenMode.CREATE | fs.OpenMode.READ_WRITE | fs.OpenMode.TRUNC);
    try {
      fs.writeSync(f.fd, on ? '1' : '0');
    } finally {
      fs.closeSync(f);
    }
  }

  /** 读回开关的真实落盘状态。文件不存在（守护没起过）当关。 */
  private readSwitch(): boolean {
    const path = this.filesDir + '/' + SWITCH_FILE;
    if (!fs.accessSync(path)) {
      return false;
    }
    try {
      return fs.readTextSync(path).trim() === '1';
    } catch (e) {
      // 读不动就当关：宁可让操作者再拨一次，也不要显示一个假的「开」。
      hilog.warn(DOMAIN, TAG, 'readSwitch: %{public}s', (e as Error).message);
      return false;
    }
  }

  /**
   * 把"请给我一份当前快照"写进请求文件。守护轮询这个文件。
   *
   * 与 writeSwitch 同款写法。CREATE 只是"不存在就建"，而应用其实**没有** create
   * 权限：文件不存在时 openSync 会抛 EACCES。那正是"采集器没在跑"的现场症状，
   * 所以这里故意不吞，交给调用方给一条指名道姓的文案。
   */
  private writeReq(on: boolean): void {
    const path = this.filesDir + '/' + REQ_FILE;
    const f = fs.openSync(path, fs.OpenMode.CREATE | fs.OpenMode.READ_WRITE | fs.OpenMode.TRUNC);
    try {
      fs.writeSync(f.fd, on ? '1' : '0');
    } finally {
      fs.closeSync(f);
    }
  }

  /**
   * 读请求文件。'1' = 还在等采集器，'0' = 它已经写完并关闭了结果文件。
   *
   * 采集器把 '0' 写在 dump 落盘**并 fclose 之后**，所以看到 '0' 就等于"文件已完整"
   * —— 不需要 stat、不需要 mtime、不需要第三个文件。
   */
  private readReq(): boolean {
    const path = this.filesDir + '/' + REQ_FILE;
    if (!fs.accessSync(path)) {
      return false;
    }
    try {
      return fs.readTextSync(path).trim() === '1';
    } catch (e) {
      // 读不动就当"已完成"：让流程往下走去读结果文件，别在这里空转满 6 秒。
      hilog.warn(DOMAIN, TAG, 'readReq: %{public}s', (e as Error).message);
      return false;
    }
  }

  /** 读采集器写的那份实时窗口。 */
  private readLive(): RawRec[] {
    return this.readJsonl(LIVE_FILE);
  }

  /**
   * 读一份采集器写出来的 JSONL。
   *
   * 文件还没出现是正常状态（守护没起，或这一路还没被用过），所以不存在就返回空、
   * 不报错。半行也丢掉：写和读之间没有锁，读到写了一半的那行，下一轮它就是完整的了。
   */
  private readJsonl(name: string): RawRec[] {
    const path = this.filesDir + '/' + name;
    if (!fs.accessSync(path)) {
      return [];
    }
    const text = fs.readTextSync(path);
    const out: RawRec[] = [];
    for (const line of text.split('\n')) {
      if (line.length === 0) {
        continue;
      }
      try {
        out.push(JSON.parse(line) as RawRec);
      } catch (e) {
        // 采集器可能正写到一半（写和读没有锁）。半行丢掉即可，
        // 下一轮它就是完整的一行了——所以这里不报错。
      }
    }
    return out;
  }

  /** 一轮：读文件 → 喂引擎 → 挑出没见过的案例 → 弹。 */
  private async tick(): Promise<void> {
    // busy：现读快照正在跑（最长 6 秒）。那期间不能让 1s 的轮询插手改
    // findings/status，否则界面上会一半是快照、一半是实时窗口，而且状态行
    // 会被 tick 覆盖回"监听中"，看起来像快照没生效。
    // snapMode：快照**已经**铺到界面上了，这一屏要留住 —— 见 freezeSnapshot()。
    if (!this.guardOn || !this.indexReady || this.pollBusy || this.busy || this.snapMode) {
      return;
    }
    this.pollBusy = true;
    try {
      const recs = this.readLive();
      this.liveLines = recs.length;
      if (recs.length === 0) {
        this.status = '监听中 · 等待 denial…';
        return;
      }

      const raws = this.rawsOf(recs);

      const resp = JSON.parse(
        await plnative.analyze(raws.join('\n'), MAX_FINDINGS)) as AnalyzeResp;
      if (!resp.ok) {
        this.err = '分析失败：' + resp.error;
        return;
      }

      const list: Finding[] = resp.findings ? resp.findings : [];
      const fresh: Finding[] = [];
      for (const f of list) {
        const k = caseKey(f);
        if (!this.seen.has(k)) {
          this.seen.add(k);
          fresh.push(f);
        }
      }

      this.findings = list;
      this.summary = resp.total + ' 条 denial → ' + resp.unique + ' 个唯一案例' +
        '（板子自带 ' + resp.board + ' / 工具造成 ' + resp.tool + '）';
      this.err = '';
      // 两个数测的不是一回事，标签必须分开写，否则看起来像自相矛盾：
      //   liveLines 是**当前这个窗口**的文件长度（每次开窗都会截断重建）
      //   seen      是**本次应用运行**累计见过的案例（跨窗口累加，不随截断回退）
      // 中途重开一次窗口就会出现「1 行 / 9 个案例」，那是对的，不是 bug。
      this.status = '监听中 · 本次窗口 ' + this.liveLines + ' 行 / 累计 ' +
        this.seen.size + ' 个案例';

      if (fresh.length > 0) {
        this.newCount += fresh.length;
        this.announce(fresh);
      }
    } catch (e) {
      // 读失败不该把开关顶掉：文件可能正被守护截断重建。
      hilog.warn(DOMAIN, TAG, 'tick: %{public}s', (e as Error).message);
    } finally {
      // 必须放 finally。上面 try 里有两条提前 return（空文件 / 分析失败），
      // 原先 pollBusy 的复位写在 try 之后 —— 于是**第一次读到空的 live.jsonl
      // 就把它永久置 true**，之后每轮 tick 在入口直接 return，界面从此定格。
      // 而"复位 → 触发 → 弹出"这条演示动线，重置会话时必然先读到空文件，
      // 所以那不是偶发竞态，是每次都会中的必然。
      this.pollBusy = false;
    }
  }

  /** 新案例：应用内先弹一条，再尽量发系统通知。 */
  private announce(fresh: Finding[]): void {
    const top = fresh[0];
    this.popTitle = top.src + ' → ' + top.tgt;
    this.popBody = top.cls + (top.op.length > 0 ? ' · ' + top.op : '') +
      '（' + originLabel(top.origin) + '）';
    this.popFix = top.fix;
    hilog.info(DOMAIN, TAG, 'new case: %{public}s', caseKey(top));

    const n = Math.min(fresh.length, NOTIFY_CAP);
    for (let i = 0; i < n; i++) {
      this.notify(fresh[i], fresh.length);
    }
  }

  /**
   * 发一条系统通知。
   *
   * 失败一律吞掉：通知要用户在设置里允许，被关掉是完全正常的状态，
   * 而应用内那条横幅不受影响 —— 所以通知是"锦上添花"，不是主路径。
   */
  private notify(f: Finding, total: number): void {
    const more = total > 1 ? '（另有 ' + (total - 1) + ' 条）' : '';
    const req: notificationManager.NotificationRequest = {
      id: this.notifyId++,
      content: {
        notificationContentType:
          notificationManager.ContentType.NOTIFICATION_CONTENT_BASIC_TEXT,
        normal: {
          title: 'PolicyLoop：' + f.src + ' → ' + f.tgt + more,
          text: f.cls + (f.op.length > 0 ? ' · ' + f.op : ''),
          additionalText: f.fix.length > 0 ? f.fix : f.verdict
        }
      }
    };
    notificationManager.publish(req).catch((e: Error) => {
      hilog.warn(DOMAIN, TAG, 'notify skipped: %{public}s', e.message);
    });
  }

  /** 拨开关。开 = 落地开关文件并清空会话状态；关 = 落地并停轮询。 */
  async applyToggle(on: boolean): Promise<void> {
    this.guardOn = on;
    this.seen = new Set();
    this.findings = [];
    this.summary = '';
    this.popTitle = '';
    this.popBody = '';
    this.popFix = '';
    this.newCount = 0;
    this.liveLines = 0;
    this.err = '';
    // 拨开关 = "重新开始看"：解除快照冻结，按钮那行提示也清掉。
    // 这也是 snapMode 唯一的解冻入口（见 freezeSnapshot）。
    this.snapMode = false;
    this.snapMsg = '';
    this.snapMsgBad = false;

    try {
      this.writeSwitch(on);
    } catch (e) {
      this.err = '开关写不下去：' + (e as Error).message;
      this.guardOn = false;
      return;
    }

    if (!on) {
      this.status = '已停止';
      return;
    }

    this.status = '已开启 · 等待采集器…';
    // 只问一次。用户拒绝之后每轮再问就是骚扰，而应用内横幅照样工作。
    if (!this.notifyAsked) {
      this.notifyAsked = true;
      try {
        await notificationManager.requestEnableNotification(
          getContext(this) as common.UIAbilityContext);
      } catch (e) {
        hilog.warn(DOMAIN, TAG, 'notification not enabled: %{public}s',
                   (e as Error).message);
      }
    }
    this.tick();
  }

  /**
   * 现读板子**此刻**的 denial 积压。
   *
   * 应用读不了 /dev/kmsg（三档 HAP 全被 neverallow 挡在外面，板子 dmesg_restrict=1），
   * 所以"现读"只能请特权侧的采集器代劳：往 snapshot.req 写 '1' 提请求，它读完
   * 落进 snapshot.jsonl，最后把 snapshot.req 写回 '0' 当完成信号。
   *
   * 为什么不做成"开个会话读几秒了事"：那会把这块板子的历史积压翻出来 —— 拨开关
   * 那条路是"从现在开始看"（--from-now），这里要的恰恰相反，是"此刻已经积了什么"。
   * 采集器那边用一次性的读源，语义正好。
   */
  async loadSnapshot(): Promise<void> {
    if (!this.indexReady || this.busy) {
      return;
    }
    this.busy = true;
    try {
      // 请求这一步单独隔离，好给一条**指名道姓**的文案。
      // 顺带纠正一个曾经的误判：应用在自己的沙箱里是**能建文件**的 ——
      // (allow normal_hap_attr normal_hap_data_file_attr (dir (... create ... add_name ...)))
      // 而 debug_hap_data_file 正是 normal_hap_data_file_attr 的成员（板子 5.0.3 策略实测）。
      // 早先"应用没有 create 权限、所以必须由采集器预建"的判断查错了主体与目标，
      // 已作废；预建现在只是为了给两侧一个确定的初始状态与 0666。
      // 所以这里真扔出来，多半是目录本身不可写，而不是 SELinux。
      try {
        this.writeReq(true);
      } catch (e) {
        this.snapMsg = '写不下请求文件：' + (e as Error).message;
        this.snapMsgBad = true;
        return;
      }

      // 等采集器把 '0' 写回来。用一个局部小循环而不是挂在 tick() 上：tick() 入口
      // `!this.guardOn` 直接返回，而"载入当前快照"在开关关着时也必须能用。
      let done = false;
      for (let i = 0; i < 24; i++) {
        await sleep(250);
        if (!this.readReq()) {
          done = true;
          break;
        }
      }
      if (!done) {
        // 超时**不**替它写回 '0'：请求还挂着，采集器下次醒来照样会服务它，
        // 只是这次界面上如实报"没回应"。
        this.snapMsg = '采集器没回应（6 秒）—— 服务在跑吗？看 install_service.sh status 第一组判据。';
        this.snapMsgBad = true;
        return;
      }

      const raws = this.rawsOf(this.readJsonl(SNAP_FILE));
      if (raws.length === 0) {
        // 采集器读成功了但一条 denial 都没有 —— 板子此刻是干净的。这是真话，
        // 不是失败，所以给一条不同于"没回应"的文案。
        this.findings = [];
        this.summary = '';
        this.freezeSnapshot('当前快照（现读）· 板子此刻没有积压的 denial');
        return;
      }
      const resp = await this.analyzeInto(raws);
      if (!resp.ok) {
        this.snapMsg = '引擎解析失败：' + resp.error;
        this.snapMsgBad = true;
        return;
      }
      this.freezeSnapshot('当前快照（现读）· ' + resp.total + ' 条 → ' + resp.unique +
        ' 个案例 —— 拨一次开关恢复实时');
    } catch (e) {
      this.snapMsg = '读快照异常：' + (e as Error).message;
      this.snapMsgBad = true;
    } finally {
      // 照 tick() 的 pollBusy 教训：复位必须走 finally，上面有好几条提前 return。
      this.busy = false;
    }
  }

  /** 回放随包发布的预录样本（9/21 采，756 行）。非实时，只作对照。 */
  async replaySample(): Promise<void> {
    if (!this.indexReady || this.snapshotText.length === 0 || this.busy) {
      return;
    }
    this.busy = true;
    try {
      const resp = await this.analyzeInto([this.snapshotText]);
      if (!resp.ok) {
        this.snapMsg = '引擎解析失败：' + resp.error;
        this.snapMsgBad = true;
        return;
      }
      this.freezeSnapshot('预录样本（9/21 采 · 非实时）· ' + resp.total + ' 条 → ' +
        resp.unique + ' 个案例 —— 拨一次开关恢复实时');
    } catch (e) {
      this.snapMsg = '分析异常：' + (e as Error).message;
      this.snapMsgBad = true;
    } finally {
      this.busy = false;
    }
  }

  /**
   * 把视图冻在这一次的结果上，并写下按钮下面那行提示。
   *
   * 必须冻结：tick() 每秒钟都在用**实时窗口**覆盖 findings / summary / status，
   * 不冻的话这一屏活不过 1 秒 —— 按了按钮、内容闪一下就没了，看起来像没生效。
   * 解冻的唯一入口是拨开关（applyToggle），那本来也是"重新开始看"的动作。
   *
   * 提示写进 snapMsg 而不是 err：err 会被 tick() 每成功一轮清空，写在那里
   * 等于只显示 1 秒。
   */
  private freezeSnapshot(msg: string): void {
    this.snapMode = true;
    this.snapMsg = msg;
    this.snapMsgBad = false;
    this.status = '已暂停实时刷新 · 显示的是快照';
  }

  /** 从采集器写的记录里取出原始 avc 行 —— 引擎吃的是原始行，不是那份 JSON。 */
  private rawsOf(recs: RawRec[]): string[] {
    const out: string[] = [];
    for (const r of recs) {
      if (r.raw !== undefined && r.raw !== null && r.raw.length > 0) {
        out.push(r.raw);
      }
    }
    return out;
  }

  /**
   * 把一批原始 denial 行交给引擎，再把结果铺到界面上。
   *
   * 只负责"把结果放上去"，失败怎么说是调用方的事 —— 所以引擎报的错**不写进
   * this.err**，那个字段会被 tick() 每成功一轮清空。
   */
  private async analyzeInto(raws: string[]): Promise<AnalyzeResp> {
    const resp = JSON.parse(
      await plnative.analyze(raws.join('\n'), MAX_FINDINGS)) as AnalyzeResp;
    if (!resp.ok) {
      return resp;
    }
    // 这一批的案例就是当前的视图 —— 所以 seen 在这里重置，而不是在按钮的入口。
    // 放在入口的话，**失败**的那次也会把累计计数清掉（界面上"累计 49 → 40"倒退）。
    this.seen = new Set();
    const list: Finding[] = resp.findings ? resp.findings : [];
    for (const f of list) {
      this.seen.add(caseKey(f));
    }
    this.findings = list;
    this.summary = resp.total + ' 条 denial → ' + resp.unique + ' 个唯一案例' +
      '（板子自带 ' + resp.board + ' / 工具造成 ' + resp.tool + '）';
    this.err = '';
    return resp;
  }

  // ------------------------------------------------------------------ 视图
  //
  // 配色一律走 $r('app.color.*')（定义在 resources/base/element/color.json）。
  // 原先这里散着 70 多处硬编码十六进制，改一处要全局找；更要紧的是
  // start_window_background 那份**也是**同一个文件 —— 它当时是 #FFFFFF，
  // 于是深色界面启动时要先闪一帧白，见 color.json 里的值。

  /**
   * 状态语义色。顶上那盏灯、开关卡片里的小点、卡片描边三处必须同色，
   * 所以只留这一个出口 —— 各写各的迟早会出现"灯是绿的、字是灰的"。
   */
  private statusTone(): Resource {
    if (this.err.length > 0) {
      return $r('app.color.err');
    }
    if (this.snapMode) {
      return $r('app.color.warn');
    }
    return this.guardOn ? $r('app.color.ok') : $r('app.color.text_3');
  }

  /** 状态灯里那两个字。完整那句话（窗口行数 / 累计案例）仍显示在开关卡片里。 */
  private statusTag(): string {
    if (this.err.length > 0) {
      return '异常';
    }
    if (this.snapMode) {
      return '快照';
    }
    return this.guardOn ? '监听中' : '已停止';
  }

  /**
   * 结论那一行的颜色。
   *
   * 引擎给的 verdict 有两种形态（见 device/selinux_adapter/.../napi_init.cpp）：
   * 要么是 `需人工介入`，要么是 `<评审结论> · <验证结论>`。前者原先和后者一样
   * 渲染成绿色 —— 于是"这条我不敢自动修"在屏幕上看起来跟"已通过"一模一样。
   * 这里按字面判一次；只影响颜色，不动引擎给的任何字段。
   */
  private verdictTone(v: string): Resource {
    return v.indexOf('需人工') >= 0 ? $r('app.color.warn') : $r('app.color.ok');
  }

  /** 品牌标：一个圆角方块 + 两个字母，没有图片资源也能立住视觉重心。 */
  @Builder
  brandMark(size: number, solid: boolean) {
    Column() {
      Text('PL')
        .fontSize(size * 0.44)
        .fontWeight(FontWeight.Bold)
        .fontColor(solid ? $r('app.color.bg') : $r('app.color.text_4'))
    }
    .width(size)
    .height(size)
    .borderRadius(size * 0.3)
    .backgroundColor(solid ? $r('app.color.accent') : $r('app.color.surface'))
    // 实心那版的描边和底色同色，等于没有 —— 这样两版共用一句，不用分叉。
    .border({ width: 1, color: solid ? $r('app.color.accent') : $r('app.color.line') })
    .justifyContent(FlexAlign.Center)
    .alignItems(HorizontalAlign.Center)
  }

  /** 小圆角标签。类型名、"新 denial" 都用它，保证同一套圆角与内边距。 */
  @Builder
  chip(label: string, fg: Resource, bg: Resource) {
    Text(label)
      .fontSize(10)
      .fontWeight(FontWeight.Medium)
      .fontColor(fg)
      .backgroundColor(bg)
      .padding({ left: 7, right: 7, top: 3, bottom: 3 })
      .borderRadius(6)
      .maxLines(1)
  }

  /** 最小修复那一行：等宽 + 高亮。弹窗与列表卡片共用，两处观感一致。 */
  @Builder
  fixLine(text: string, lines: number) {
    Text(text)
      .fontSize(11)
      .fontColor($r('app.color.info'))
      .fontFamily('monospace')
      .lineHeight(16)
      .width('100%')
      .maxLines(lines)
      .textOverflow({ overflow: TextOverflow.Ellipsis })
  }

  @Builder
  header() {
    Row() {
      this.brandMark(30, true)

      Column() {
        Text('PolicyLoop 控制台')
          .fontSize(16)
          .fontWeight(FontWeight.Bold)
          .fontColor($r('app.color.text'))
          .maxLines(1)
        // 索引版本留在首屏：现场被问"你这套规则是哪一版"时，不用翻文档。
        Text('索引 ' + this.indexName)
          .fontSize(10)
          .fontColor($r('app.color.text_3'))
          .margin({ top: 3 })
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
      }
      .alignItems(HorizontalAlign.Start)
      .layoutWeight(1)
      .margin({ left: 10, right: 8 })

      this.statusPill()
    }
    .width('100%')
    .alignItems(VerticalAlign.Center)
    .padding({ left: 18, right: 18, top: 14, bottom: 14 })
  }

  /** 首屏右上角那盏灯：一个点 + 两个字。开关开没开不用读整句话。 */
  @Builder
  statusPill() {
    Row({ space: 6 }) {
      Circle({ width: 7, height: 7 }).fill(this.statusTone())
      Text(this.statusTag())
        .fontSize(10)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.statusTone())
    }
    .padding({ left: 9, right: 11, top: 5, bottom: 5 })
    .backgroundColor($r('app.color.surface'))
    .border({ width: 1, color: $r('app.color.line') })
    .borderRadius(20)
  }

  @Builder
  switchCard() {
    Column() {
      Row() {
        Column() {
          Text('运行时捕获')
            .fontSize(15)
            .fontWeight(FontWeight.Medium)
            .fontColor($r('app.color.text'))
          Text('读到 denial 就给出最小修复 · 板端独立，不依赖 PC')
            .fontSize(11)
            .fontColor($r('app.color.text_3'))
            .margin({ top: 4 })
            .maxLines(2)
        }
        .alignItems(HorizontalAlign.Start)
        .layoutWeight(1)
        .margin({ right: 10 })

        Toggle({ type: ToggleType.Switch, isOn: this.guardOn })
          .selectedColor($r('app.color.accent'))
          .enabled(!this.busy && this.indexReady)
          .onChange((v: boolean) => {
            this.applyToggle(v);
          })
      }
      .width('100%')
      .alignItems(VerticalAlign.Center)

      Divider()
        .color($r('app.color.line'))
        .margin({ top: 14, bottom: 12 })

      // 状态行：一个点 + 一句话。点的颜色与顶上那盏灯同源（statusTone）。
      Row({ space: 8 }) {
        Circle({ width: 6, height: 6 }).fill(this.statusTone())
        Text(this.status)
          .fontSize(12)
          .fontColor($r('app.color.text_2'))
          .layoutWeight(1)
          .maxLines(2)
      }
      .width('100%')
      .alignItems(VerticalAlign.Center)

      // 两个动作并排，主次分明：主按钮实心、次按钮浅底。
      Row({ space: 8 }) {
        Button(this.busy ? '分析中…' : '载入当前快照')
          .fontSize(13)
          .fontWeight(FontWeight.Medium)
          .height(36)
          .layoutWeight(1)
          .backgroundColor($r('app.color.accent'))
          .fontColor($r('app.color.bg'))
          .enabled(!this.busy && this.indexReady)
          .onClick(() => {
            this.loadSnapshot();
          })

        Button('回放预录样本')
          .fontSize(13)
          .height(36)
          .backgroundColor($r('app.color.surface_hi'))
          .fontColor($r('app.color.text_2'))
          .onClick(() => {
            // busy 的拦截交给 replaySample 自己（入口已有 guard），
            // 不在这里加 .enabled —— Row 上禁用子控件的点击行为不如入口判断可靠。
            this.replaySample();
          })
      }
      .width('100%')
      .margin({ top: 14 })

      // 按钮这条动线自己的结果/报错。紧贴按钮下面，因为按完按钮眼睛就在这儿。
      if (this.snapMsg.length > 0) {
        Text(this.snapMsg)
          .fontSize(11)
          .fontColor(this.snapMsgBad ? $r('app.color.err') : $r('app.color.ok'))
          .width('100%')
          .margin({ top: 10 })
      }

      // 第二条数据来源的**常驻标注**。
      //
      // 主按钮指向的永远是**此刻这块板子上的**东西；这份 9/21 的样本是**素材**。
      // 被问"是不是预录的"时，屏幕上这一行就是答案 —— 所以"非实时"三个字必须
      // 留在明面上。原先是 11px 的文字链压在最暗的灰上（#5C646E on #1A1F26），
      // 几乎看不见，等于把这条标注藏了起来。
      Text('预录样本 9/21 采 · 756 行 · 非实时，仅供对照')
        .fontSize(10)
        .fontColor($r('app.color.text_4'))
        .width('100%')
        .margin({ top: 10 })
    }
    .width('100%')
    .padding(16)
    .backgroundColor($r('app.color.surface'))
    .border({ width: 1, color: $r('app.color.line') })
    .borderRadius(14)
  }

  /** 弹出来的那条。实时演示里它是最该被看见的东西，所以给足视觉权重。 */
  @Builder
  popCard() {
    Column() {
      Row() {
        this.chip('新 denial', $r('app.color.bg'), $r('app.color.warn'))
        Text(this.popBody)
          .fontSize(11)
          .fontColor($r('app.color.text_3'))
          .layoutWeight(1)
          .margin({ left: 8 })
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
        Text('收起')
          .fontSize(11)
          .fontColor($r('app.color.text_3'))
          .margin({ left: 8 })
          .onClick(() => {
            this.popTitle = '';
            this.popBody = '';
            this.popFix = '';
          })
      }
      .width('100%')
      .alignItems(VerticalAlign.Center)

      Text(this.popTitle)
        .fontSize(15)
        .fontWeight(FontWeight.Medium)
        .fontColor($r('app.color.text'))
        .width('100%')
        .margin({ top: 10 })
        .maxLines(2)
        .textOverflow({ overflow: TextOverflow.Ellipsis })

      if (this.popFix.length > 0) {
        Column() {
          Text('最小修复')
            .fontSize(10)
            .fontColor($r('app.color.text_4'))
            .width('100%')
            .margin({ bottom: 5 })
          this.fixLine(this.popFix, 4)
        }
        .width('100%')
        .padding(10)
        .backgroundColor($r('app.color.bg'))
        .borderRadius(8)
        .margin({ top: 10 })
      }

      Row() {
        Text('本次会话已发现 ' + this.newCount + ' 个新案例')
          .fontSize(11)
          .fontColor($r('app.color.ok'))
          .layoutWeight(1)
        Text('板端引擎解读')
          .fontSize(10)
          .fontColor($r('app.color.text_4'))
      }
      .width('100%')
      .alignItems(VerticalAlign.Center)
      .margin({ top: 10 })
    }
    .width('100%')
    .padding(14)
    .backgroundColor($r('app.color.pop_bg'))
    .border({ width: 1, color: $r('app.color.pop_line') })
    .borderRadius(14)
    .margin({ top: 12 })
  }

  @Builder
  findingCard(f: Finding) {
    Column() {
      Row() {
        // 主体/目标两段分开上色：一眼能看出箭头两边谁是发起方。
        // Span 挂在同一个 Text 下，所以超长时按一行整体省略，不会两段各截各的。
        Text() {
          Span(f.src)
            .fontColor($r('app.color.text'))
            .fontWeight(FontWeight.Medium)
          Span('  →  ')
            .fontColor($r('app.color.text_4'))
          Span(f.tgt)
            .fontColor($r('app.color.text_2'))
        }
        .fontSize(13)
        .layoutWeight(1)
        .maxLines(1)
        .textOverflow({ overflow: TextOverflow.Ellipsis })

        this.chip(f.cls, $r('app.color.warn'), $r('app.color.warn_soft'))
      }
      .width('100%')
      .alignItems(VerticalAlign.Center)

      if (f.op.length > 0) {
        Text(f.op)
          .fontSize(11)
          .fontColor($r('app.color.text_3'))
          .width('100%')
          .margin({ top: 6 })
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
      }

      if (f.fix.length > 0) {
        Column() {
          this.fixLine(f.fix, 3)
        }
        .width('100%')
        .padding(9)
        .backgroundColor($r('app.color.bg'))
        .borderRadius(7)
        .margin({ top: 8 })
      }

      Row() {
        Text(f.verdict)
          .fontSize(10)
          .fontColor(this.verdictTone(f.verdict))
          .layoutWeight(1)
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
        Text(originLabel(f.origin))
          .fontSize(10)
          .fontColor(f.origin === 'board' ? $r('app.color.text_3') : $r('app.color.text_4'))
      }
      .width('100%')
      .alignItems(VerticalAlign.Center)
      .margin({ top: 9 })
    }
    .width('100%')
    .padding(14)
    .backgroundColor($r('app.color.surface'))
    .border({ width: 1, color: $r('app.color.line') })
    .borderRadius(12)
    .margin({ bottom: 10 })
  }

  /** 空状态。复用品牌标（描边灰版），让"这里本该有东西"也有重心。 */
  @Builder
  emptyState() {
    Column() {
      this.brandMark(44, false)

      Text(this.snapMode
        ? '这一份快照里没有 denial'
        : (this.guardOn ? '监听中，还没有 denial' : '开关关闭，未开始监听'))
        .fontSize(13)
        .fontColor($r('app.color.text_3'))
        .margin({ top: 16 })

      Text(this.snapMode
        ? '拨一次开关恢复实时刷新'
        : (this.guardOn ? '一有 denial 就会出现在这里，并弹出通知' : '打开上面的开关，开始实时捕获'))
        .fontSize(11)
        .fontColor($r('app.color.text_4'))
        .margin({ top: 6 })

      // 沙箱路径留在屏幕上：现场最容易出错的就是"两边看的不是同一个目录"。
      Text('沙箱 ' + this.sandbox)
        .fontSize(10)
        .fontColor($r('app.color.text_4'))
        .margin({ top: 18 })
        .maxLines(1)
        .textOverflow({ overflow: TextOverflow.Ellipsis })
    }
    .width('100%')
    .layoutWeight(1)
    .justifyContent(FlexAlign.Center)
    .alignItems(HorizontalAlign.Center)
    .padding({ left: 16, right: 16, bottom: 48 })
  }

  build() {
    Column() {
      this.header()

      Divider().color($r('app.color.line'))

      Column() {
        this.switchCard()

        if (this.err.length > 0) {
          Row({ space: 8 }) {
            Circle({ width: 6, height: 6 }).fill($r('app.color.err'))
            Text(this.err)
              .fontSize(11)
              .fontColor($r('app.color.err'))
              .layoutWeight(1)
          }
          .width('100%')
          .alignItems(VerticalAlign.Top)
          .padding(12)
          .backgroundColor($r('app.color.err_soft'))
          .border({ width: 1, color: $r('app.color.err_soft') })
          .borderRadius(10)
          .margin({ top: 12 })
        }

        if (this.popTitle.length > 0) {
          this.popCard()
        }

        if (this.summary.length > 0) {
          Column() {
            Row() {
              Text('案例明细')
                .fontSize(12)
                .fontWeight(FontWeight.Medium)
                .fontColor($r('app.color.text_2'))
              Text(this.findings.length + ' 个案例')
                .fontSize(11)
                .fontColor($r('app.color.text_4'))
            }
            .width('100%')
            .justifyContent(FlexAlign.SpaceBetween)
            .alignItems(VerticalAlign.Center)

            Text(this.summary)
              .fontSize(10)
              .fontColor($r('app.color.text_4'))
              .width('100%')
              .margin({ top: 5 })
              .maxLines(2)
          }
          .width('100%')
          .margin({ top: 18 })
        }

        if (this.findings.length === 0) {
          this.emptyState()
        } else {
          List({ space: 0 }) {
            ForEach(this.findings, (f: Finding) => {
              ListItem() {
                this.findingCard(f)
              }
            }, (f: Finding) => caseKey(f))
          }
          .width('100%')
          .layoutWeight(1)
          .scrollBar(BarState.Auto)
          .margin({ top: 10 })
        }
      }
      .width('100%')
      .layoutWeight(1)
      .padding({ left: 18, right: 18, bottom: 18 })
    }
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.bg'))
  }
}
