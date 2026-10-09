/**
 * PolicyLoop 板端引擎的 ArkTS 声明。
 *
 * 两个函数都把结果作为 **JSON 字符串**交回，而不是结构化对象：JSON 的编码与
 * 转义在原生侧只有一个实现（引擎自带的 JsonString），跨语言边界时不会因为两边
 * 各转一次而出现双重转义。ArkTS 侧 JSON.parse 一下就得到 Finding。
 */

declare namespace plnative {
  /**
   * 解析一份 PLI 索引并留在原生侧，后续 analyze 复用。
   *
   * 索引有两万条规则、解析要 200ms 以上，所以只加载一次，且是异步的。
   * 返回 `{ok, error, rev, rules, source}`。`rev` 是索引内容哈希的前 12 位，
   * 报告要能对着它复现。
   */
  function loadIndex(indexText: string): Promise<string>;

  /**
   * 对一段 AVC 日志做去重、分类与最小修复。
   *
   * *limit* 限制列出的条数；统计（total/unique/board/tool）始终走全量。
   * 返回 `{ok, error, total, unique, board, tool, findings[]}`，
   * 字段与 PC 侧控制台的 /state 同形。
   */
  function analyze(logText: string, limit?: number): Promise<string>;
}

export default plnative;
