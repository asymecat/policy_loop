/**
 * PolicyLoop 控制台。
 *
 * 板子这一侧就是全部：引擎编在 libplnative.so 里，索引与日志以 rawfile 随包
 * 发布，应用自己解析 AVC 日志、自己出最小修复。拔掉 USB 照常运行。
 *
 * 采集不在应用的能力范围内，而且从来没在过 —— PC 在环时也是 hdc shell 在
 * `dmesg | grep 'avc:'`。应用域读不到 /dev/kmsg（三条 neverallow）、没有
 * syslog_read、板子还开着 dmesg_restrict=1。这是策略划的线。
 */
import UIAbility from '@ohos.app.ability.UIAbility';
import window from '@ohos.window';
import hilog from '@ohos.hilog';

const DOMAIN: number = 0x0000;
const TAG: string = 'PL_CONSOLE';

export default class EntryAbility extends UIAbility {
  onWindowStageCreate(windowStage: window.WindowStage): void {
    windowStage.loadContent('pages/Index', (err) => {
      if (err.code) {
        hilog.error(DOMAIN, TAG, 'loadContent failed: %{public}s', JSON.stringify(err));
      }
    });
  }
}
