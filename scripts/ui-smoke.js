#!/usr/bin/env node
/*
 * 控制台 UI 冒烟测试（无浏览器）。
 *
 * 为什么需要：`console_tests` 只能对 app.js 做「文本里包含某字符串」的断言，
 * 于是「IIFE 提前闭合 → 后半段被甩到全局作用域 → 加载期
 * ReferenceError: $ is not defined → 测试页整页失效」这种 bug 一路全绿发版。
 *
 * 这里用最小 DOM 桩真正**执行** app.js，并逐个驱动页面加载器与几个关键交互，
 * 断言：① 全程无异常；② 每个页面确实渲染出了内容；③ 日志详情同时给出
 * 「原文」与「发给上游」两个面板。
 *
 * 用法：node scripts/ui-smoke.js        （失败时非零退出）
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(ROOT, 'assets', 'index.html'), 'utf8');
const js = fs.readFileSync(path.join(ROOT, 'assets', 'app.js'), 'utf8');

const failures = [];
const check = (cond, msg) => { if (!cond) failures.push(msg); };

/* ------------------------------------------------------------------ *
 * 最小 DOM 桩
 * ------------------------------------------------------------------ */
function El(tag, opts = {}) {
  const el = {
    tagName: String(tag || 'div').toUpperCase(),
    id: opts.id || '',
    hidden: false,
    value: '',
    textContent: '',
    _html: '',
    _q: {},          // querySelector 缓存（同一选择器返回同一实例，模拟真实 DOM 节点）
    className: opts.className || '',
    checked: false,
    disabled: false,
    title: '',
    type: opts.type || 'text',
    dataset: opts.dataset || {},
    style: {},
    selectionStart: 0,
    _listeners: {},
    _attrs: {},
    classList: {
      _s: new Set(String(opts.className || '').split(/\s+/).filter(Boolean)),
      add(...c) { c.forEach(x => this._s.add(x)); },
      remove(...c) { c.forEach(x => this._s.delete(x)); },
      contains(c) { return this._s.has(c); },
      toggle(c, force) {
        const on = force === undefined ? !this._s.has(c) : !!force;
        if (on) this._s.add(c); else this._s.delete(c);
        return on;
      },
    },
    setAttribute(k, v) { this._attrs[k] = String(v); },
    getAttribute(k) { return Object.prototype.hasOwnProperty.call(this._attrs, k) ? this._attrs[k] : null; },
    addEventListener(t, fn) { (this._listeners[t] = this._listeners[t] || []).push(fn); },
    removeEventListener() {},
    focus() {}, select() {}, setSelectionRange() {},
    // innerHTML 是 setter：重设内容即作废已缓存的子节点（真实 DOM 里旧节点也没了）
    get innerHTML() { return this._html; },
    set innerHTML(v) { this._html = String(v); this._q = {}; },
    // 只支持属性选择器（app.js 只用这种）：只要 innerHTML 里出现过该属性名就返回一个
    // 持久子节点，使「测试写入 textarea.value → app 通过 querySelector 读回」这条
    // 真实 DOM 交互链在桩里也能成立。
    querySelector(sel) {
      const attr = String(sel).replace(/^\[|\]$/g, '');
      if (!attr || !this._html.includes(attr)) return null;
      if (!this._q[attr]) this._q[attr] = El('div');
      return this._q[attr];
    },
    querySelectorAll() { return []; },
    closest() { return null; },
    matches() { return false; },
    fire(type, ev) { (this._listeners[type] || []).forEach(fn => fn(ev)); },
  };
  return el;
}

// 从 index.html 取真实 id / tab / page / preset 形状
const ids = [...html.matchAll(/id="([^"]+)"/g)].map(m => m[1]);
const tabPages = [...html.matchAll(/class="tab[^"]*"\s+data-page="([^"]+)"/g)].map(m => m[1]);
const pageIds = [...html.matchAll(/class="page[^"]*"\s+id="([^"]+)"/g)].map(m => m[1]);
const presetNames = [...html.matchAll(/data-preset="([^"]+)"/g)].map(m => m[1]);

const byId = new Map();
for (const id of ids) {
  const type = /password/.test(new RegExp(`id="${id}"[^>]*type="password"`)) ? 'password' : 'text';
  byId.set(id, El('div', { id, type }));
}
check(ids.length > 40, `index.html 里 id 太少（${ids.length}），DOM 桩可能没解析到`);

const tabEls = tabPages.map(p => El('button', { className: 'tab', dataset: { page: p } }));
const pageEls = pageIds.map(pid => El('section', { className: 'page', id: pid }));
const presetEls = presetNames.map(n => El('button', { dataset: { preset: n } }));

const documentEl = El('html');
documentEl.setAttribute('data-theme', 'dark');
const documentStub = {
  documentElement: documentEl,
  getElementById: id => byId.get(id) || null,
  querySelector: () => null,
  querySelectorAll: sel => {
    if (sel === '.tab') return tabEls;
    if (sel === '.page') return pageEls;
    if (sel === '[data-preset]') return presetEls;
    return [];
  },
  addEventListener() {},
};

/* ------------------------------------------------------------------ *
 * 网络桩：按端点返回形状贴近真实的数据
 * ------------------------------------------------------------------ */
const cfgPayload = () => ({
  server: { port: 18701, bind: '127.0.0.1' },
  upstream: { target: 'http://127.0.0.1:9', extra_headers: {} },
  mask: {
    enabled: true,
    builtin_rules: { API_KEY: true, PHONE: true, EMAIL: false },
    custom_words: { 张三: 'PERSON', 李四: 'PERSON', Acme: 'ACME', 'example.com': 'DOMAIN' },
    custom_word_groups: ['PERSON', 'ACME', 'DOMAIN', 'EMPTY_GROUP'],
    sensitive_disabled: [],
    sensitive_word_disabled: { PERSON: ['李四'] },
    sensitive_word_whole: ['Acme'],
    secret_prefixes: ['sk-'],
  },
  fail_closed: true,
  response_scan: true,
  stream_response: true,
  command_block: { mode: 'observe' },
  log_retention_days: 7,
  panel_token: 'tok-abc',
});

const maskEvent = {
  id: 7, ts: 1758600000.5, type: 'MASK', method: 'POST', path: '/v1/chat/completions',
  status: 200, protocol: 'chat_completions', model: 'gpt-4o', sid: 'abc-1f2e3d4c',
  stream_mode: 'non_stream', stream_actual: 'whole', req_bytes: 2100, count: 2,
  new_count: 1, reused_count: 1, mask_ms: 12.3,
  dialog: '我的电话是13800138000，邮箱 a@b.com',
  masked_dialog: '我的电话是{{PHONE_bcdfgh}}，邮箱 {{EMAIL_qwrtzx}}',
  items: [
    { label: 'PHONE', tok: '{{PHONE_bcdfgh}}', original: '13800138000', cred: false, length: 11 },
    { label: 'EMAIL', tok: '{{EMAIL_qwrtzx}}', original: 'a@b.com', cred: false, length: 7 },
  ],
};
// 老事件：没有 masked_dialog，必须走「按命中明细推算」兜底
const legacyEvent = {
  id: 6, ts: 1758599000, type: 'MASK', method: 'POST', path: '/v1/messages',
  status: 200, model: 'claude-3', count: 1, mask_ms: 3,
  dialog: '客户张三的电话是13800138000',
  items: [{ label: 'PHONE', tok: '{{PHONE_jkmnpq}}', original: '13800138000', cred: false, length: 11 }],
};
const errEvent = {
  id: 5, ts: 1758598000, type: 'ERR', method: 'POST', path: '/v1/chat/completions',
  status: 502, reason: 'upstream_failed', message: 'connect refused', items: [],
};

const auditPayload = {
  events: [
    { id: 1, ts: 1758600001, signal_type: 'response_poison', severity: 'HIGH', evidence: 'CANARY_0_deadbeef', sid: 'abc', host: 'api.example.com', method: 'POST', path: '/v1/chat/completions' },
    { id: 2, ts: 1758600002, signal_type: 'error_leak', severity: 'LOW', evidence: 'stack trace', sid: 'def', host: 'api.example.com', method: 'POST', path: '/v1/messages' },
  ],
};

const calls = [];
async function fetchStub(url, opts) {
  calls.push(url);
  const u = String(url);
  let body;
  if (u.includes('/console/api/status')) {
    body = { ok: true, port: 18701, bind: '127.0.0.1', upstream_target: 'http://127.0.0.1:9', paused: false, fail_closed: true, config_version: 3, counters: { requests: 12, masked: 5, restored: 4, blocked: 1, bypassed: 2, errors: 1 }, sessions: 1 };
  } else if (u.includes('/console/api/stats/today')) {
    body = { requests: 12, alerts: 1, tokens_total: 3456 };
  } else if (u.includes('/console/api/logs/detail')) {
    const id = Number((u.match(/id=(\d+)/) || [])[1]);
    body = id === 6 ? legacyEvent : id === 5 ? errEvent : maskEvent;
  } else if (u.includes('/console/api/logs')) {
    body = { events: [maskEvent, legacyEvent, errEvent], total: 3, offset: 0, limit: 100 };
  } else if (u.includes('/console/api/audit/events')) {
    body = auditPayload;
  } else if (u.includes('/console/api/mask/test')) {
    body = { ok: true, mode: 'text', masked: '我是{{PERSON_bcdfgh}}，手机 {{PHONE_qwrtzx}}', restored: '我是张三，手机 13800138000', count: 2, elapsed_ms: 1.2, isolated: true,
      items: [{ label: 'PERSON', tok: '{{PERSON_bcdfgh}}', original: '张三', cred: false, length: 2 }, { label: 'PHONE', tok: '{{PHONE_qwrtzx}}', original: '13800138000', cred: false, length: 11 }] };
  } else if (u.includes('/console/api/config/patch')) {
    body = { ok: true, config: cfgPayload(), warnings: [] };
  } else if (u.includes('/console/api/config')) {
    body = cfgPayload();
  } else {
    body = { ok: true };
  }
  return { ok: true, status: 200, statusText: 'OK', json: async () => JSON.parse(JSON.stringify(body)) };
}

/* ------------------------------------------------------------------ *
 * 执行 app.js
 * ------------------------------------------------------------------ */
const errors = [];
const sandbox = {
  console: { log: () => {}, warn: () => {}, error: (...a) => errors.push(a.join(' ')) },
  document: documentStub,
  localStorage: {
    _m: { maskit_token: 'tok-abc' }, // 直接进入已登录态
    getItem(k) { return Object.prototype.hasOwnProperty.call(this._m, k) ? this._m[k] : null; },
    setItem(k, v) { this._m[k] = String(v); },
    removeItem(k) { delete this._m[k]; },
  },
  fetch: fetchStub,
  AbortController,
  crypto: { getRandomValues: a => { for (let i = 0; i < a.length; i++) a[i] = (i * 7 + 3) & 0xff; return a; } },
  navigator: { clipboard: { writeText: async () => {} } },
  confirm: () => true,
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: t => clearTimeout(t),
  // 定时器不真跑，否则进程不退出
  setInterval: () => 0,
  clearInterval: () => {},
  Date, Math, JSON, Number, String, Object, Array, Set, Map, RegExp, Error, Promise, encodeURIComponent, parseInt, isNaN,
};
// window：既是全局对象，也要支撑 addEventListener / location / history
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
sandbox.location = { hash: '', href: 'http://localhost/console' };
sandbox.history = { replaceState: (_s, _t, url) => {
  const h = String(url || '');
  sandbox.location.hash = h.startsWith('#') ? h : '#' + h;
} };
sandbox.window.addEventListener = (type, fn) => { (sandbox.__winListeners[type] = sandbox.__winListeners[type] || []).push(fn); };
sandbox.__winListeners = {};

const tick = (n = 6) => new Promise(async res => {
  for (let i = 0; i < n; i++) await new Promise(r => setTimeout(r, 0));
  res();
});

(async () => {
  try {
    vm.createContext(sandbox);
    vm.runInContext(js, sandbox, { filename: 'assets/app.js' });
  } catch (e) {
    failures.push(`app.js 加载期抛异常：${e && e.message}`);
    report();
    return;
  }
  await tick();

  // ---- 概览（启动后应已渲染）----
  check(byId.get('statCards').innerHTML.includes('请求总数'), '概览：统计卡未渲染');
  check(byId.get('statusTable').innerHTML.includes('监听'), '概览：状态表未渲染');

  // ---- 逐页驱动 ----
  const drive = async name => {
    const tab = tabEls.find(t => t.dataset.page === name) || El('button', { dataset: { page: name } });
    byId.get('tabs').fire('click', { target: { closest: sel => (sel === '.tab' ? tab : null) } });
    await tick();
  };

  // 规则页
  await drive('rules');
  check(byId.get('ruleToggles').innerHTML.includes('PHONE'), '规则页：内置规则未渲染');
  const nav0 = byId.get('cwNav').innerHTML;
  check(nav0.includes('PERSON'), '规则页：分组导航未渲染');
  check(nav0.includes('EMPTY_GROUP'), '规则页：空分组没有保留（分组必须能独立存在）');
  check(nav0.includes('新建分组'), '规则页：缺「新建分组」入口');

  // 切到 PERSON 分组（导航点击）
  byId.get('cwNav').fire('click', {
    target: { closest: sel => (sel === '[data-cw-group-pick]' ? { dataset: { cwGroupPick: 'PERSON' } } : null) },
  });
  await tick(2);
  const main0 = byId.get('cwMain').innerHTML;
  check(main0.includes('张三'), '规则页：切分组后词表未渲染');
  check(main0.includes('整组启用'), '规则页：缺整组开关');
  // 关键需求：加词不需要再填分组名 —— 当前分组内就有添加框
  check(main0.includes('向「PERSON」添加敏感词'), '规则页：当前分组内缺添加框');
  check(main0.includes('data-cw-addwords'), '规则页：缺添加输入框');
  check(!main0.includes('data-cw-label'), '规则页：不应再要求逐次填写分组名');

  // 在 PERSON 分组里加词：只往当前分组的输入框里打字，**不需要再提供分组名**
  const addBox = byId.get('cwMain').querySelector('[data-cw-addwords]');
  check(addBox !== null, '规则页：拿不到当前分组的添加输入框');
  addBox.value = '王五';
  const patchesBefore = calls.filter(u => u.includes('/config/patch')).length;
  byId.get('cwMain').fire('click', {
    target: { closest: sel => (sel === '[data-cw-addok]' ? {} : null) },
  });
  await tick(2);
  check(
    calls.filter(u => u.includes('/config/patch')).length > patchesBefore,
    '加词：未发出配置补丁'
  );

  // 停用「张三」
  const p2 = calls.filter(u => u.includes('/config/patch')).length;
  byId.get('cwMain').fire('change', {
    target: { matches: sel => sel === '[data-cw-word]', dataset: { cwWord: '张三' }, checked: false },
  });
  await tick(2);
  check(calls.filter(u => u.includes('/config/patch')).length > p2, '逐词停用：未发出配置补丁');
  check(byId.get('cwMain').innerHTML.includes('张三'), '敏感词交互后词表丢失内容');

  // 新建分组：点「新建分组」→ 内联输入 → 创建（分组自身要落盘）
  byId.get('cwNav').fire('click', { target: { closest: sel => (sel === '[data-cw-newgroup]' ? {} : null) } });
  await tick(2);
  check(byId.get('cwNav').innerHTML.includes('data-cw-newgroup-input'), '新建分组：未出现内联输入框');
  const ngBox = byId.get('cwNav').querySelector('[data-cw-newgroup-input]');
  check(ngBox !== null, '新建分组：拿不到内联输入框');
  ngBox.value = 'CONTRACT_NO';
  const p3 = calls.filter(u => u.includes('/config/patch')).length;
  byId.get('cwNav').fire('click', { target: { closest: sel => (sel === '[data-cw-newgroup-ok]' ? {} : null) } });
  await tick(2);
  check(calls.filter(u => u.includes('/config/patch')).length > p3, '新建分组：未落盘');

  // 日志页
  await drive('logs');
  const listHtml = byId.get('logList').innerHTML;
  check(listHtml.includes('MASK') && listHtml.includes('ERR'), '日志页：列表未渲染');
  const detail = byId.get('logDetail').innerHTML;
  check(detail.includes('原文（客户端发出）'), '日志详情：缺「原文」面板');
  check(detail.includes('发给上游（已脱敏）'), '日志详情：缺「发给上游」面板');
  check(detail.includes('class="tok"'), '日志详情：占位符未高亮');
  check(detail.includes('13800138000'), '日志详情：原文应可见');
  check(!detail.includes('>13800138000<') || detail.includes('发给上游'), '日志详情：结构异常');
  check(byId.get('logMeta').textContent.includes('共 3 条'), '日志页：缺总数');

  // 切到「老事件」（无 masked_dialog）→ 必须走推算兜底
  byId.get('logList').fire('click', {
    target: { closest: sel => (sel === '.lrow' ? { dataset: { logId: '6' } } : null) },
  });
  await tick();
  const legacy = byId.get('logDetail').innerHTML;
  check(legacy.includes('按命中明细推算'), '老事件：未走「按命中明细推算」兜底');
  check(legacy.includes('{{PHONE_jkmnpq}}'), '老事件：推算结果缺占位符');

  // 审计页
  await drive('audit');
  const alist = byId.get('auditList').innerHTML;
  check(alist.includes('response_poison'), '审计页：列表未渲染');
  check(byId.get('auditDetail').innerHTML.includes('CANARY_0_deadbeef'), '审计页：证据未渲染');

  // 测试页
  await drive('test');
  byId.get('testInput').value = '我是张三，手机 13800138000';
  await byId.get('btnRunTest').fire('click', {});
  await tick();
  check(byId.get('testResult').hidden === false, '测试页：结果区未显示');
  check(byId.get('testMasked').innerHTML.includes('class="tok"'), '测试页：脱敏结果未高亮占位符');
  check(byId.get('testRestored').innerHTML.includes('13800138000'), '测试页：还原结果缺失');
  check(byId.get('testItems').innerHTML.includes('PERSON'), '测试页：命中明细未渲染');
  check(byId.get('testSummary').textContent.includes('命中 2 项'), '测试页：摘要未更新');

  // 设置页
  await drive('settings');
  check(byId.get('panelToken').value === 'tok-abc', '设置页：令牌未回填');
  check(byId.get('upstreamTarget').value.includes('127.0.0.1:9'), '设置页：上游地址未回填');

  // 令牌显示/隐藏
  byId.get('btnToggleToken').fire('click', {});
  check(byId.get('panelToken').type === 'text', '令牌「显示」开关无效');

  check(errors.length === 0, `控制台出现错误输出：${errors.join(' | ')}`);
  report();
})();

function report() {
  if (failures.length) {
    console.error('❌ UI 冒烟失败：');
    for (const f of failures) console.error('   - ' + f);
    process.exit(1);
  }
  console.log('✅ UI 冒烟通过（加载 + 6 个页面渲染 + 日志/审计/测试/敏感词交互）');
  process.exit(0);
}
