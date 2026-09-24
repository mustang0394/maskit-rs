/* Maskit-RS 控制台（原生 JS，无构建步骤，整文件一个 IIFE） */
(function () {
  'use strict';

  const API = '/console/api';
  const LS_TOKEN = 'maskit_token';
  const LS_THEME = 'maskit_theme';
  const API_TIMEOUT_MS = 30000;
  let TOKEN = localStorage.getItem(LS_TOKEN) || '';

  /* ==================== 主题 ==================== */
  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(LS_THEME, theme);
    const icon = document.getElementById('themeIcon');
    if (icon) icon.textContent = theme === 'dark' ? '☀' : '☾';
    const btn = document.getElementById('themeToggle');
    if (btn) btn.title = theme === 'dark' ? '切换到浅色主题' : '切换到深色主题';
  }
  applyTheme(localStorage.getItem(LS_THEME) || 'dark');

  /* ==================== 基础工具 ==================== */
  function $(id) { return document.getElementById(id); }
  function esc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }
  function fmtTs(ts) {
    if (!ts) return '—';
    const d = new Date(ts * 1000);
    const p = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }
  function fmtTime(ts) {
    if (!ts) return '';
    const d = new Date(ts * 1000);
    const p = n => String(n).padStart(2, '0');
    return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }
  function fmtBytes(n) {
    if (!n) return '';
    if (n < 1024) return n + 'B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + 'KB';
    return (n / 1024 / 1024).toFixed(1) + 'MB';
  }
  function fmtMs(v) { return v == null ? '' : Number(v).toFixed(1) + 'ms'; }

  let toastTimer = null;
  function toast(msg, isErr) {
    const el = $('toast');
    el.textContent = msg;
    el.className = 'toast' + (isErr ? ' err' : '');
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, 3200);
  }

  /* ==================== 文本高亮 ==================== */
  // 占位符形态（与引擎一致）：标签 1-12 位 [A-Za-z0-9_]，后缀 6 位辅音或留存 hex6。
  // 另兼容模型把花括号「整理」掉的裸形态（`PHONE_bcdfgh`）—— 还原的宽松遍
  // 就是冲着这种形态去的，日志里也常能看到，标出来才知道哪里是占位符。
  const PH_BRACED = /\{\{[A-Za-z0-9_]{1,12}_[0-9a-zA-Z]{6}\}\}/g;
  const PH_BARE = /(?<![A-Za-z0-9_])[A-Z][A-Z0-9]{1,11}_[0-9a-z]{6}(?![A-Za-z0-9_])/g;

  /**
   * 在**已转义**的文本上标出占位符与指定原文，返回安全 HTML。
   * 先算好所有区间再一次性拼接，避免「替换出的标签又被后续替换命中」。
   */
  function highlight(text, needles) {
    const src = esc(text == null ? '' : text);
    if (!src) return '';
    const marks = [];
    const collect = re => {
      const rx = new RegExp(re.source, 'g');
      let m;
      while ((m = rx.exec(src)) !== null) {
        marks.push({ s: m.index, e: m.index + m[0].length, kind: 'tok' });
        if (m[0].length === 0) rx.lastIndex++;
      }
    };
    collect(PH_BRACED);
    collect(PH_BARE);
    const uniq = [...new Set((needles || []).filter(Boolean))].sort((a, b) => b.length - a.length);
    for (const raw of uniq) {
      const n = esc(raw);
      if (!n) continue;
      let i = 0;
      while ((i = src.indexOf(n, i)) !== -1) {
        const s = i, e = i + n.length;
        if (!marks.some(r => s < r.e && e > r.s)) marks.push({ s, e, kind: 'hit' });
        i = e;
      }
    }
    marks.sort((a, b) => a.s - b.s || b.e - a.e);
    let out = '', pos = 0;
    for (const r of marks) {
      if (r.s < pos) continue;
      out += src.slice(pos, r.s);
      const seg = src.slice(r.s, r.e);
      out += r.kind === 'tok' ? `<span class="tok">${seg}</span>` : `<mark class="hit">${seg}</mark>`;
      pos = r.e;
    }
    return out + src.slice(pos);
  }

  /** 用命中明细把原文还原成「发给上游」的形态（老事件没有 masked_dialog 时兜底）。 */
  function deriveMasked(text, items) {
    let out = String(text || '');
    const pairs = (items || [])
      .filter(it => it.original && (it.tok || it.token))
      .map(it => [it.original, it.tok || it.token])
      .sort((a, b) => b[0].length - a[0].length);
    for (const [orig, tok] of pairs) out = out.split(orig).join(tok);
    return out;
  }

  async function copyFrom(el, btn) {
    try {
      await navigator.clipboard.writeText(el.textContent);
      const old = btn.textContent;
      btn.textContent = '已复制';
      setTimeout(() => { btn.textContent = old; }, 1200);
    } catch { toast('剪贴板不可用', true); }
  }

  /** 空状态 HTML。 */
  function emptyBox(text) { return `<div class="d-empty">${esc(text)}</div>`; }

  /* ==================== API ==================== */
  async function api(path, opts) {
    // 必须带超时：上游卡住时，展开日志详情等操作会永久停在「加载中…」
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), API_TIMEOUT_MS);
    try {
      const res = await fetch(API + path, Object.assign({
        headers: Object.assign({ 'Content-Type': 'application/json' },
          TOKEN ? { Authorization: 'Bearer ' + TOKEN } : {}),
        signal: ctrl.signal,
      }, opts || {}));
      if (res.status === 401) {
        showLogin('令牌无效或已过期，请重新输入');
        throw new Error('unauthorized');
      }
      if (!res.ok) {
        let msg = res.status + ' ' + res.statusText;
        try { const j = await res.json(); msg = j.error || msg; } catch (e) {}
        throw new Error(msg);
      }
      return res.json();
    } catch (e) {
      if (e && e.name === 'AbortError') throw new Error('请求超时（' + (API_TIMEOUT_MS / 1000) + 's）');
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }

  /** 配置补丁：segs 优先（键含 '.' 时点分 path 会被切错）。返回新配置。 */
  async function patch(segs, value) {
    const r = await api('/config/patch', {
      method: 'POST', body: JSON.stringify({ segs, value }),
    });
    return r.config;
  }

  /* ==================== 登录 ==================== */
  function showLogin(errMsg) {
    $('loginScreen').hidden = false;
    $('app').hidden = true;
    $('loginError').hidden = !errMsg;
    if (errMsg) $('loginError').textContent = errMsg;
    setTimeout(() => $('tokenInput').focus(), 50);
  }
  function enterApp() {
    $('loginScreen').hidden = true;
    $('app').hidden = false;
    loadDashboard().catch(e => toast(e.message, true));
  }

  $('loginForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const btn = $('loginBtn');
    const input = $('tokenInput');
    TOKEN = input.value.trim();
    if (!TOKEN) { $('loginError').textContent = '请输入令牌'; $('loginError').hidden = false; return; }
    btn.disabled = true;
    btn.textContent = '验证中…';
    try {
      await api('/status');
      localStorage.setItem(LS_TOKEN, TOKEN);
      $('loginError').hidden = true;
      enterApp();
    } catch (e) {
      if (e.message !== 'unauthorized') {
        $('loginError').textContent = e.message;
        $('loginError').hidden = false;
      }
    } finally {
      btn.disabled = false;
      btn.textContent = '进入控制台';
    }
  });

  $('logoutBtn').addEventListener('click', () => {
    TOKEN = ''; localStorage.removeItem(LS_TOKEN);
    $('tokenInput').value = '';
    stopLogAuto();
    showLogin();
  });

  $('themeToggle').addEventListener('click', () => {
    const cur = document.documentElement.getAttribute('data-theme');
    applyTheme(cur === 'dark' ? 'light' : 'dark');
  });

  /* ==================== 页面切换 ==================== */
  const PAGES = ['dashboard', 'rules', 'logs', 'audit', 'test', 'settings'];
  const loaders = {};
  let currentPage = 'dashboard';

  /** 从 URL hash 取页面名（支持刷新保持当前页 / 直接书签某个页）。 */
  function hashPage() {
    try {
      const h = String((window.location && window.location.hash) || '').replace(/^#\/?/, '');
      return PAGES.includes(h) ? h : '';
    } catch (e) { return ''; }
  }

  function switchPage(name) {
    if (!PAGES.includes(name)) name = 'dashboard';
    currentPage = name;
    document.querySelectorAll('.tab').forEach(t => {
      const on = t.dataset.page === name;
      t.classList.toggle('active', on);
      t.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.id === 'page-' + name));
    // 刷新/回退后仍停在当前页（用 replaceState，不往历史里堆垃圾条目）
    try {
      if (window.history && window.history.replaceState) {
        window.history.replaceState(null, '', '#' + name);
      }
    } catch (e) { /* file:// 等场景忽略 */ }
    if (name !== 'logs') stopLogAuto();
    if (loaders[name]) loaders[name]().catch(e => toast(e.message, true));
  }
  $('tabs').addEventListener('click', ev => {
    const t = ev.target.closest('.tab');
    if (t) switchPage(t.dataset.page);
  });
  window.addEventListener('hashchange', () => {
    const p = hashPage();
    if (p && p !== currentPage) switchPage(p);
  });

  /* ==================== 概览 ==================== */
  async function loadDashboard() {
    const [status, today] = await Promise.all([api('/status'), api('/stats/today')]);
    const c = status.counters || {};
    $('statCards').innerHTML = [
      ['请求总数', c.requests], ['已脱敏', c.masked], ['已还原', c.restored],
      ['已阻断', c.blocked], ['透传', c.bypassed], ['错误', c.errors],
      ['今日 token', today.tokens_total],
    ].map(([k, v]) =>
      `<div class="card"><div class="v">${v == null ? 0 : esc(v)}</div><div class="k">${esc(k)}</div></div>`).join('');

    $('statusTable').innerHTML = [
      ['监听', status.bind + ':' + status.port],
      ['上游', status.upstream_target || '（未配置）'],
      ['脱敏状态', status.paused ? '已暂停（纯透传）' : '运行中'],
      ['fail-closed', status.fail_closed ? '开启' : '关闭'],
      ['配置版本', status.config_version],
      ['活跃会话', status.sessions],
      ['今日请求', today.requests],
      ['今日告警', today.alerts],
    ].map(([k, v]) => `<tr><td>${esc(k)}</td><td class="mono">${esc(v)}</td></tr>`).join('');

    const el = $('topStatus');
    el.textContent = (status.paused ? '已暂停脱敏 · ' : '') +
      (status.upstream_target ? '上游已配置' : '未配置上游');
    el.className = 'status ' + (status.upstream_target ? 'ok' : 'bad');
  }
  loaders.dashboard = loadDashboard;

  $('btnPause').addEventListener('click', () =>
    api('/proxy/pause', { method: 'POST' }).then(() => { toast('已暂停脱敏（纯透传）'); return loadDashboard(); })
       .catch(e => toast(e.message, true)));
  $('btnResume').addEventListener('click', () =>
    api('/proxy/resume', { method: 'POST' }).then(() => { toast('已恢复脱敏'); return loadDashboard(); })
       .catch(e => toast(e.message, true)));

  /* ==================== 规则：内置规则 ==================== */
  const RULE_LABELS = {
    API_KEY: 'API Key / 密钥前缀', ACCESS_KEY: '云厂商 AccessKey', CARD: '银行卡（Luhn 校验）',
    CONNSTR: '连接串密码', EMAIL: '邮箱地址', HKID: '港澳通行证', IBAN: 'IBAN 银行账号',
    IDCARD: '身份证（15/18 位）', IP_INTERNAL: '内网 IP（10.x / 172.16-31）',
    IP_PRIVATE: '内网 IP（192.168 / 169.254 / 100.64）', IP_PUBLIC: '公网 IP',
    IPV6_PRIVATE: 'IPv6 私网（fe80:: / fc00::）', IPV6_PUBLIC: '公网 IPv6（2000::/3）',
    JWT: 'JWT 令牌', LANDLINE: '固定电话',
    MAC: 'MAC 地址', PHONE: '手机号', PLATE: '车牌号', PRIVATE_KEY: 'PEM / OpenSSH 私钥',
    SECRET: '键值对凭据（password=…）', SSH_PUBKEY: 'SSH 公钥（rsa / ed25519 / ecdsa）',
    TOKEN: 'Bearer Token', USCC: '统一社会信用代码',
  };
  // ⚠️ 必须与服务端 default_builtin_rules() 保持一致（控制台「恢复默认」按这个来）
  const RULE_DEFAULT_ON = ['API_KEY', 'CARD', 'CONNSTR', 'EMAIL', 'IDCARD', 'LANDLINE', 'PHONE', 'SSH_PUBKEY'];

  // 事件委托只注册一次（放在 IIFE 顶层）—— 早期写在 loadRules() 里，
  // 而 loadRules 会被反复调用，每次都新建箭头函数、无法被去重，
  // 于是监听器不断累积：切一个开关打 N 次 PATCH、弹 N 个 toast。
  $('ruleToggles').addEventListener('change', async ev => {
    const cb = ev.target.closest('input[data-rule]');
    if (!cb) return;
    const item = cb.closest('.rule-item');
    item.classList.toggle('on', cb.checked);
    try {
      const cfg = await patch(['mask', 'builtin_rules', cb.dataset.rule], cb.checked);
      renderRuleSummary(cfg.mask.builtin_rules || {});
      toast(`${cb.dataset.rule} 已${cb.checked ? '开启' : '关闭'}`);
    } catch (e) {
      cb.checked = !cb.checked;
      item.classList.toggle('on', cb.checked);
      toast('保存失败：' + e.message, true);
    }
  });

  function renderRuleSummary(rules) {
    const keys = Object.keys(rules);
    const n = keys.filter(k => rules[k]).length;
    $('ruleSummary').textContent = `已开启 ${n} / ${keys.length}`;
  }

  async function loadRules() {
    const cfg = await api('/config');
    const rules = cfg.mask.builtin_rules || {};
    const keys = Object.keys(rules).sort();

    $('ruleToggles').innerHTML = keys.map(k => {
      const name = RULE_LABELS[k] || k;
      return `<label class="rule-item ${rules[k] ? 'on' : ''}" title="${esc(name)}（${esc(k)}）">
        <input type="checkbox" data-rule="${esc(k)}" ${rules[k] ? 'checked' : ''}/>
        <span class="rule-text">
          <span class="rule-name">${esc(name)}</span>
          <span class="rule-key">${esc(k)}</span>
        </span>
      </label>`;
    }).join('');
    renderRuleSummary(rules);
    await loadWords(cfg);
    renderPrefixes(cfg);
  }
  loaders.rules = loadRules;

  $('btnRulesDefault').addEventListener('click', async () => {
    if (!confirm('把所有内置规则恢复为默认开关状态？')) return;
    try {
      const cfg = await api('/config');
      const cur = cfg.mask.builtin_rules || {};
      const next = {};
      Object.keys(cur).forEach(k => { next[k] = RULE_DEFAULT_ON.includes(k); });
      await patch(['mask', 'builtin_rules'], next);
      toast('已恢复默认');
      loadRules();
    } catch (e) { toast(e.message, true); }
  });

  $('btnRulesAll').addEventListener('click', async () => {
    if (!confirm('开启全部内置规则？误报率会上升（车牌 / 公网 IP / 私网 IP 等）。')) return;
    try {
      const cfg = await api('/config');
      const cur = cfg.mask.builtin_rules || {};
      const next = {};
      Object.keys(cur).forEach(k => { next[k] = true; });
      await patch(['mask', 'builtin_rules'], next);
      toast('已开启全部规则');
      loadRules();
    } catch (e) { toast(e.message, true); }
  });

  /* ==================== 规则：密钥前缀 ==================== */
  function renderPrefixes(cfg) {
    const prefixes = cfg.mask.secret_prefixes || [];
    $('prefixList').innerHTML = prefixes.length
      ? prefixes.map(p => `<span class="chip"><span class="chip-text mono">${esc(p)}</span>
            <button data-del-prefix="${esc(p)}" aria-label="删除">×</button></span>`).join('')
      : '<span class="hint">未配置前缀规则</span>';
  }

  $('btnAddPrefix').addEventListener('click', async () => {
    const p = $('newPrefix').value.trim();
    if (!p) return toast('请输入前缀', true);
    try {
      const cfg = await api('/config');
      const list = (cfg.mask.secret_prefixes || []).slice();
      if (list.includes(p)) { toast('该前缀已存在', true); return; }
      list.push(p);
      await patch(['mask', 'secret_prefixes'], list);
      $('newPrefix').value = '';
      toast('已添加前缀 ' + p);
      loadRules();
    } catch (e) { toast(e.message, true); }
  });

  $('prefixList').addEventListener('click', async ev => {
    const b = ev.target.closest('button[data-del-prefix]');
    if (!b) return;
    try {
      const cfg = await api('/config');
      const list = (cfg.mask.secret_prefixes || []).filter(x => x !== b.dataset.delPrefix);
      await patch(['mask', 'secret_prefixes'], list);
      toast('已删除前缀 ' + b.dataset.delPrefix);
      loadRules();
    } catch (e) { toast(e.message, true); }
  });

  /* ==================== 规则：自定义敏感词（分组是独立实体） ==================== */
  // 「分组」在配置里是一等公民：`mask.custom_word_groups` 保存**有序**的组名，
  // `mask.custom_words` 保存 {词: 分组}。组可以只有名字没有词（空盒子），
  // 所以「新建分组」能落盘、刷新后还在；加词也只需在当前选中的组里输入，
  // 不必每加一次词就重打一次分组名。
  const cw = { cfg: null, label: null, search: '', onlyDisabled: false, addingGroup: false, renaming: false };

  /** 占位符标签 ASCII 化（与服务端 safe_label 一致：非 [A-Z0-9] 剔除，≤12，空则 TERM）。 */
  function safeLabel(label) {
    const s = String(label || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12);
    return s || 'TERM';
  }
  /** 多词切分：换行 / 逗号 / 顿号 / 分号 / 空白。 */
  function splitWords(text) {
    return [...new Set(
      String(text || '').split(/[\n\r,，、;；\s]+/).map(s => s.trim()).filter(Boolean)
    )];
  }
  const isAsciiWord = w => /^[\x20-\x7e]+$/.test(w);

  /**
   * 从配置抽出分组模型。
   *
   * 分组顺序 = 已声明的顺序；手工编辑 config.json 加进来的「未声明」分组
   * （词表里有、声明表里没有）追加在后面，保证它们不会凭空消失。
   */
  function wmodel(cfg) {
    const words = cfg.mask.custom_words || {};
    const byGroup = new Map();
    for (const [w, l] of Object.entries(words)) {
      const key = (l || 'TERM');
      if (!byGroup.has(key)) byGroup.set(key, []);
      byGroup.get(key).push(w);
    }
    // 声明表里出现过、或作为 disabled/wordOff 出现过的组名，也要保留展示，
    // 否则「词被删光但组还在声明里」的组会消失，用户没法清掉它。
    const extra = [
      ...(cfg.mask.sensitive_disabled || []),
      ...Object.keys(cfg.mask.sensitive_word_disabled || {}),
    ];
    const declared = (cfg.mask.custom_word_groups || []).slice();
    // 顺序：先按声明顺序，再把「未声明但词表/开关表里出现过」的组补在后面。
    const final = [];
    const push = g => { if (g && !final.includes(g)) final.push(g); };
    for (const raw of declared) push(String(raw || '').trim());
    for (const g of byGroup.keys()) push(g);
    for (const g of extra) push(g);
    return {
      order: final,
      byGroup,
      off: new Set(cfg.mask.sensitive_disabled || []),
      wordOff: cfg.mask.sensitive_word_disabled || {},
      whole: new Set(cfg.mask.sensitive_word_whole || []),
    };
  }

  function wordEnabled(m, label, word) {
    if (m.off.has(label)) return false;
    return !((m.wordOff[label] || []).includes(word));
  }

  /** 当前配置里属于该分组的词（有序）。 */
  function groupWords(cfg, label) {
    const out = [];
    for (const [w, l] of Object.entries(cfg.mask.custom_words || {})) {
      if ((l || 'TERM') === label) out.push(w);
    }
    return out;
  }

  function currentWords(cfg) {
    return Object.assign({}, cfg.mask.custom_words || {});
  }

  /** 把「分组声明 + 词表 + 两个开关表 + 整词表」一次性写回（只发变化的键）。 */
  async function cwSave(next, opt = {}) {
    let cfg = cw.cfg;
    if (next.groups) cfg = await patch(['mask', 'custom_word_groups'], next.groups);
    if (next.words) cfg = await patch(['mask', 'custom_words'], next.words);
    if (opt.sensitive_disabled) cfg = await patch(['mask', 'sensitive_disabled'], opt.sensitive_disabled);
    if (opt.wordOff) cfg = await patch(['mask', 'sensitive_word_disabled'], opt.wordOff);
    if (opt.whole) cfg = await patch(['mask', 'sensitive_word_whole'], opt.whole);
    cw.cfg = cfg;
    renderWords();
    return cfg;
  }

  function renderWords() {
    const cfg = cw.cfg;
    if (!cfg) return;
    const m = wmodel(cfg);
    const groups = m.order;

    if (!groups.length) cw.label = null;
    else if (!groups.includes(cw.label)) cw.label = groups[0];

    // ---- 左侧：分组导航 ----
    const nav = groups.map(g => {
      const ws = groupWords(cfg, g);
      const off = m.off.has(g);
      const disabledN = ws.filter(w => !wordEnabled(m, g, w)).length;
      return `<button class="nav-item ${g === cw.label ? 'active' : ''} ${off ? 'off' : ''}"
                data-cw-group-pick="${esc(g)}" title="${esc(g)}">
          <span class="nav-dot"></span>
          <span class="nav-name">${esc(g)}</span>
          <span class="nav-count">${ws.length}</span>
          ${disabledN ? `<span class="hint mono">${disabledN}关</span>` : ''}
        </button>`;
    }).join('');

    const addForm = cw.addingGroup
      ? `<div class="nav-form">
           <input data-cw-newgroup-input placeholder="新分组名，如 PERSON" autocomplete="off" />
           <div class="nav-form-actions">
             <button class="btn btn-sm btn-primary" data-cw-newgroup-ok>创建</button>
             <button class="btn btn-sm" data-cw-newgroup-cancel>取消</button>
           </div>
         </div>`
      : `<button class="nav-item nav-add" data-cw-newgroup>＋ 新建分组</button>`;

    $('cwNav').innerHTML = (groups.length ? nav : '') + addForm
      + (groups.length ? '' : `<div class="cw-empty hint">还没有分组<br>点上面「新建分组」开始</div>`);

    // ---- 右侧：当前分组 ----
    const label = cw.label;
    if (!label) {
      $('cwMain').innerHTML = emptyBox('先在左侧新建一个分组');
      return;
    }
    const all = groupWords(cfg, label).sort((a, b) => a.localeCompare(b));
    const q = cw.search.trim().toLowerCase();
    const rows = all.filter(w => {
      if (q && !w.toLowerCase().includes(q)) return false;
      if (cw.onlyDisabled && wordEnabled(m, label, w)) return false;
      return true;
    });
    const groupOff = m.off.has(label);
    const isDeclared = (cfg.mask.custom_word_groups || []).includes(label);
    const labelMismatch = safeLabel(label) !== label;

    $('cwMain').innerHTML = `
      <div class="cw-head">
        <div class="cw-title">
          ${cw.renaming
            ? `<input data-cw-rename-input value="${esc(label)}" aria-label="分组名" />
                 <button class="btn btn-sm btn-primary" data-cw-rename-ok>保存</button>
                 <button class="btn btn-sm" data-cw-rename-cancel>取消</button>`
            : `<b>${esc(label)}</b>
               <span class="hint mono">{{${esc(safeLabel(label))}_xxxxxx}}</span>
               <span class="hint">${all.length} 词${all.length !== rows.length ? `（显示 ${rows.length}）` : ''}</span>
               <button class="btn btn-sm" data-cw-rename>重命名</button>
               ${labelMismatch
                 ? `<span class="cw-note" title="占位符标签只保留 A-Z0-9（最多 12 位），中文等字符会被剔除">⚠ 分组名含非 ASCII，占位符前缀用 ${esc(safeLabel(label))}</span>`
                 : ''}
               ${isDeclared ? '' : '<span class="hint" title="该分组只存在于词表里（如手工编辑过 config.json），保存改动后会被登记进声明表">（未登记）</span>'}
               `}
        </div>
        <div class="cw-head-actions panel-actions">
          <label class="switch-inline" title="关闭后该分组下所有词都不再命中">
            <input type="checkbox" data-cw-group="${esc(label)}" ${groupOff ? '' : 'checked'} /> 整组启用
          </label>
          <button class="btn btn-sm" data-cw-bulk="on">全部启用</button>
          <button class="btn btn-sm" data-cw-bulk="off">全部停用</button>
          <button class="btn btn-sm btn-warn" data-cw-delgroup="${esc(label)}">删除分组</button>
        </div>
      </div>
      ${groupOff ? `<div class="note warn">该分组已被「整组停用」—— 下面的逐词开关暂时不生效。</div>` : ''}

      <div class="cw-addbox">
        <div class="cw-addbox-title">向「${esc(label)}」添加敏感词</div>
        <textarea data-cw-addwords rows="2" spellcheck="false"
          placeholder="每行一个词（也支持逗号 / 顿号 / 空格分隔）。以 re: 开头则按正则处理。"></textarea>
        <div class="cw-addbox-actions">
          <button class="btn btn-primary btn-sm" data-cw-addok>添加到「${esc(label)}」</button>
          <span class="hint" data-cw-addhint></span>
        </div>
      </div>

      <div class="cw-bar">
        <input class="cw-search" data-cw-search placeholder="在该分组内搜索…" value="${esc(cw.search)}" />
        <label class="switch-inline">
          <input type="checkbox" data-cw-onlydisabled ${cw.onlyDisabled ? 'checked' : ''} /> 仅显示已停用
        </label>
      </div>
      ${rows.length ? `<table class="cmp cw-table"><thead><tr>
          <th>词</th><th>占位符</th><th title="整词匹配：词两侧加边界，防 Acme 命中 AcmeCorp；仅对 ASCII 词有效">整词</th>
          <th>启用</th><th></th>
        </tr></thead><tbody>${rows.map(w => {
          const on = wordEnabled(m, label, w);
          const singleChar = [...w].length === 1;
          const wholeApplicable = isAsciiWord(w) && !singleChar;
          const wholeCell = !wholeApplicable
            ? `<span class="hint" title="${singleChar ? '单字词自动加边界' : '整词匹配仅对 ASCII 词有效'}">—</span>`
            : `<input type="checkbox" data-cw-whole="${esc(w)}" ${m.whole.has(w) ? 'checked' : ''} />`;
          return `<tr>
            <td class="cw-word">${esc(w)}</td>
            <td class="mono cmp-tok">{{${esc(safeLabel(label))}_xxxxxx}}</td>
            <td>${wholeCell}</td>
            <td><input type="checkbox" data-cw-word="${esc(w)}" ${on ? 'checked' : ''} /></td>
            <td><button class="btn btn-sm btn-icon" data-cw-del="${esc(w)}" aria-label="删除">✕</button></td>
          </tr>`;
        }).join('')}</tbody></table>`
        : `<div class="cw-empty">${all.length ? '没有符合筛选条件的词' : '该分组下还没有词 —— 用上面的输入框添加'}</div>`}
    `;
  }

  async function loadWords(cfg) {
    cw.cfg = cfg || await api('/config');
    cw.addingGroup = false;
    cw.renaming = false;
    renderWords();
  }

  /* ---- 左侧：新建 / 选择 / 重命名分组 ---- */
  $('cwNav').addEventListener('click', async ev => {
    const t = ev.target;
    try {
      if (t.closest('[data-cw-newgroup]')) {
        cw.addingGroup = true; cw.renaming = false;
        renderWords();
        const inp = $('cwNav').querySelector('[data-cw-newgroup-input]');
        if (inp) inp.focus();
        return;
      }
      if (t.closest('[data-cw-newgroup-cancel]')) { cw.addingGroup = false; renderWords(); return; }
      if (t.closest('[data-cw-newgroup-ok]')) {
        const inp = $('cwNav').querySelector('[data-cw-newgroup-input]');
        const name = (inp ? inp.value : '').trim();
        if (!name) { toast('请输入分组名', true); return; }
        const groups = (cw.cfg.mask.custom_word_groups || []).slice();
        if (groups.includes(name) || groupWords(cw.cfg, name).length) {
          toast('分组「' + name + '」已存在', true);
          cw.label = name; cw.addingGroup = false; renderWords();
          return;
        }
        await cwSave({ groups: [...groups, name] });
        cw.label = name; cw.addingGroup = false;
        renderWords();
        toast('已创建分组「' + name + '」，现在往里加词');
        return;
      }
      const pick = t.closest('[data-cw-group-pick]');
      if (pick) {
        cw.label = pick.dataset.cwGroupPick;
        cw.search = ''; cw.onlyDisabled = false; cw.renaming = false;
        renderWords();
      }
    } catch (e) { toast('保存失败：' + e.message, true); }
  });

  $('cwNav').addEventListener('keydown', ev => {
    if (ev.target.matches('[data-cw-newgroup-input]') && ev.key === 'Enter') {
      ev.preventDefault();
      const btn = $('cwNav').querySelector('[data-cw-newgroup-ok]');
      if (btn) btn.click();
    }
  });

  /* ---- 右侧：交互（事件委托） ---- */
  $('cwMain').addEventListener('click', async ev => {
    const t = ev.target;
    const cfg = cw.cfg;
    if (!cfg) return;
    const m = wmodel(cfg);
    const label = cw.label;
    try {
      // 重命名分组
      if (t.closest('[data-cw-rename]')) { cw.renaming = true; renderWords(); return; }
      if (t.closest('[data-cw-rename-cancel]')) { cw.renaming = false; renderWords(); return; }
      if (t.closest('[data-cw-rename-ok]')) {
        const inp = $('cwMain').querySelector('[data-cw-rename-input]');
        const name = (inp ? inp.value : '').trim();
        if (!name) { toast('分组名不能为空', true); return; }
        if (name === label) { cw.renaming = false; renderWords(); return; }
        if ((cfg.mask.custom_word_groups || []).includes(name) || groupWords(cfg, name).length) {
          toast('分组「' + name + '」已存在', true);
          return;
        }
        // 词表跟着改标签；停用表跟着搬；整词表按词走不用动
        const words = currentWords(cfg);
        for (const w of groupWords(cfg, label)) words[w] = name;
        const wordOff = JSON.parse(JSON.stringify(m.wordOff));
        if (wordOff[label]) { wordOff[name] = wordOff[label]; delete wordOff[label]; }
        const groups = (cfg.mask.custom_word_groups || []).map(g => (g === label ? name : g));
        await cwSave({ groups, words }, {
          sensitive_disabled: [...m.off].map(g => (g === label ? name : g)),
          wordOff,
        });
        cw.label = name;
        cw.renaming = false;
        renderWords();
        toast(`分组已重命名为「${name}」（占位符前缀随之变化）`);
        return;
      }

      // 添加词（当前分组，无需再填分组名）
      if (t.closest('[data-cw-addok]')) {
        const box = $('cwMain').querySelector('[data-cw-addwords]');
        const list = splitWords(box ? box.value : '');
        if (!list.length) { toast('请输入至少一个敏感词', true); return; }
        if (list.some(w => w.length > 200)) { toast('单个敏感词不能超过 200 字符', true); return; }
        const words = currentWords(cfg);
        let moved = 0, added = 0;
        for (const w of list) {
          if (Object.prototype.hasOwnProperty.call(words, w)) {
            if (words[w] !== label) { words[w] = label; moved++; }
          } else { words[w] = label; added++; }
        }
        // 顺手把该分组登记进声明表（手工建的组也能被固化下来）
        const groups = (cfg.mask.custom_word_groups || []).includes(label)
          ? undefined
          : [...(cfg.mask.custom_word_groups || []), label];
        await cwSave(groups ? { groups, words } : { words });
        if (box) box.value = '';
        const parts = [];
        if (added) parts.push(`新增 ${added} 个`);
        if (moved) parts.push(`${moved} 个从别的分组移过来`);
        toast(`已加入「${label}」${parts.length ? '（' + parts.join('，') + '）' : ''}`);
        return;
      }

      // 删除单个词
      const del = t.closest('[data-cw-del]');
      if (del) {
        const w = del.dataset.cwDel;
        const words = currentWords(cfg);
        delete words[w];
        const wordOff = JSON.parse(JSON.stringify(m.wordOff));
        for (const g of Object.keys(wordOff)) {
          wordOff[g] = wordOff[g].filter(x => x !== w);
          if (!wordOff[g].length) delete wordOff[g];
        }
        await cwSave({ words }, {
          wordOff,
          whole: [...m.whole].filter(x => x !== w),
        });
        toast('已删除「' + w + '」');
        return;
      }

      // 删除分组（连同它的词与声明）
      const delg = t.closest('[data-cw-delgroup]');
      if (delg) {
        const g = delg.dataset.cwDelgroup;
        const n = groupWords(cfg, g).length;
        if (!confirm(`删除分组「${g}」${n ? `及其 ${n} 个词` : ''}？`)) return;
        const words = currentWords(cfg);
        for (const w of groupWords(cfg, g)) delete words[w];
        const wordOff = Object.assign({}, m.wordOff);
        delete wordOff[g];
        await cwSave(
          { groups: (cfg.mask.custom_word_groups || []).filter(x => x !== g), words },
          {
            sensitive_disabled: [...m.off].filter(x => x !== g),
            wordOff,
            whole: [...m.whole].filter(w => groupWords(cfg, g).includes(w) === false),
          },
        );
        if (cw.label === g) cw.label = null;
        renderWords();
        toast(`已删除分组「${g}」`);
        return;
      }

      // 全部启用 / 全部停用（当前分组）
      const bulk = t.closest('[data-cw-bulk]');
      if (bulk) {
        const ws = groupWords(cfg, label);
        if (bulk.dataset.cwBulk === 'on') {
          const wordOff = Object.assign({}, m.wordOff);
          delete wordOff[label];
          await cwSave({}, { sensitive_disabled: [...m.off].filter(g => g !== label), wordOff });
        } else {
          const wordOff = Object.assign({}, m.wordOff);
          wordOff[label] = ws.slice();
          await cwSave({}, { wordOff });
        }
        toast(`「${label}」已${bulk.dataset.cwBulk === 'on' ? '全部启用' : '全部停用'}`);
      }
    } catch (e) { toast('保存失败：' + e.message, true); }
  });

  $('cwMain').addEventListener('change', async ev => {
    const t = ev.target;
    const cfg = cw.cfg;
    if (!cfg) return;
    const m = wmodel(cfg);
    try {
      if (t.matches('[data-cw-group]')) {
        const g = t.dataset.cwGroup;
        const off = new Set(m.off);
        if (t.checked) off.delete(g); else off.add(g);
        await cwSave({}, { sensitive_disabled: [...off] });
        toast(`「${g}」已${t.checked ? '启用' : '停用'}`);
        return;
      }
      if (t.matches('[data-cw-word]')) {
        const w = t.dataset.cwWord;
        const g = cw.label;
        const wordOff = JSON.parse(JSON.stringify(m.wordOff));
        const set = new Set(wordOff[g] || []);
        if (t.checked) set.delete(w); else set.add(w);
        if (set.size) wordOff[g] = [...set]; else delete wordOff[g];
        await cwSave({}, { wordOff });
        return;
      }
      if (t.matches('[data-cw-whole]')) {
        const w = t.dataset.cwWhole;
        const whole = new Set(m.whole);
        if (t.checked) whole.add(w); else whole.delete(w);
        await cwSave({}, { whole: [...whole] });
        return;
      }
      if (t.matches('[data-cw-onlydisabled]')) {
        cw.onlyDisabled = t.checked;
        renderWords();
      }
    } catch (e) { toast('保存失败：' + e.message, true); }
  });

  $('cwMain').addEventListener('input', ev => {
    const t = ev.target;
    if (t.matches('[data-cw-addwords]')) {
      const n = splitWords(t.value).length;
      const box = $('cwMain').querySelector('[data-cw-addhint]');
      if (box) {
        const dup = splitWords(t.value).filter(w =>
          Object.prototype.hasOwnProperty.call(cw.cfg.mask.custom_words || {}, w)).length;
        box.textContent = n
          ? `${n} 个词${dup ? `（${dup} 个已存在，会改到本分组）` : ''}`
          : '';
      }
      return;
    }
    if (t.matches('[data-cw-search]')) {
      cw.search = t.value;
      const pos = t.selectionStart;
      renderWords();
      const el = $('cwMain').querySelector('[data-cw-search]');
      if (el) { el.focus(); try { el.setSelectionRange(pos, pos); } catch (e) {} }
    }
  });

  $('cwMain').addEventListener('keydown', ev => {
    const t = ev.target;
    if (t.matches('[data-cw-rename-input]') && ev.key === 'Enter') {
      ev.preventDefault();
      const btn = $('cwMain').querySelector('[data-cw-rename-ok]');
      if (btn) btn.click();
      return;
    }
    // 添加框里 Ctrl/Cmd+Enter 直接提交（多行粘贴时不用去够按钮）
    if (t.matches('[data-cw-addwords]') && (ev.metaKey || ev.ctrlKey) && ev.key === 'Enter') {
      ev.preventDefault();
      const btn = $('cwMain').querySelector('[data-cw-addok]');
      if (btn) btn.click();
    }
  });

  /* ==================== 日志（主从双栏） ==================== */
  const log = { type: '', q: '', offset: 0, limit: 100, total: 0, rows: [], sel: null, auto: false, timer: null };

  function stopLogAuto() {
    if (log.timer) { clearInterval(log.timer); log.timer = null; }
    const cb = $('logAuto');
    if (cb) cb.checked = false;
    log.auto = false;
  }
  function startLogAuto() {
    stopLogAuto();
    log.auto = true;
    log.timer = setInterval(() => {
      if (currentPage !== 'logs') { stopLogAuto(); return; }
      log.offset = 0;
      loadLogs().catch(() => {});
    }, 5000);
  }

  function logRowHtml(e) {
    const t = String(e.type || '');
    const flags = [];
    if (e.reason) flags.push(esc(e.reason));
    if (e.unknown_shape) flags.push('未知形态');
    if (e.stream_mode) {
      const actual = e.stream_actual || 'whole';
      flags.push(actual !== e.stream_mode ? `流式不符(${esc(e.stream_mode)}→${esc(actual)})` : esc(e.stream_mode));
    }
    const stat = [];
    if (e.count) stat.push(`脱敏 ${e.count}`);
    if (e.restored) stat.push(`还原 ${e.restored}`);
    if (e.unresolved) stat.push(`未还原 ${e.unresolved}`);
    if (e.degraded) stat.push(`容错 ${e.degraded}`);
    if (e.status >= 400) stat.push(`HTTP ${e.status}`);
    const hits = e.count || e.restored || (e.items || []).length;
    return `<button class="lrow ${log.sel === e.id ? 'active' : ''}" data-log-id="${e.id}" role="option"
              aria-selected="${log.sel === e.id ? 'true' : 'false'}">
        <span class="lrow-top">
          <span class="lrow-time">${esc(fmtTime(e.ts))}</span>
          <span class="badge ${esc(t)}">${esc(t)}</span>
          ${hits ? `<span class="hint">${hits} 命中</span>` : ''}
          ${e.mask_ms != null ? `<span class="hint mono">${esc(fmtMs(e.mask_ms))}</span>` : ''}
        </span>
        <span class="lrow-sub"><span class="lrow-path">${esc(e.method || '')} ${esc(e.path || '')}</span></span>
        ${flags.length ? `<span class="lrow-sub">${flags.join(' · ')}</span>` : ''}
        ${stat.length ? `<span class="lrow-sub mono">${stat.join(' · ')}</span>` : ''}
      </button>`;
  }

  function logDetailHtml(e) {
    const type = String(e.type || '');
    const items = e.items || [];
    const needles = items.map(it => it.original).filter(Boolean);
    const parts = [];

    parts.push(`<header class="d-head">
      <div class="d-head-main">
        <span class="badge ${esc(type)}">${esc(type)}</span>
        <span class="mono d-path">${esc(e.method || '')} ${esc(e.path || '')}</span>
        ${e.status ? `<span class="hint mono">HTTP ${esc(e.status)}</span>` : ''}
      </div>
      <div class="d-head-sub">${esc(fmtTs(e.ts))}${e.protocol ? ' · ' + esc(e.protocol) : ''}${e.model ? ' · ' + esc(e.model) : ''}</div>
    </header>`);

    const kv = [
      ['耗时', e.mask_ms != null ? fmtMs(e.mask_ms) : ''],
      ['首字节', e.first_byte_ms != null ? fmtMs(e.first_byte_ms) : ''],
      ['上游耗时', e.upstream_ms != null ? fmtMs(e.upstream_ms) : ''],
      ['请求体', fmtBytes(e.req_bytes)],
      ['响应体', fmtBytes(e.resp_bytes)],
      ['新增/复用', `${e.new_count || 0} / ${e.reused_count || 0}`],
      ['会话', e.sid || ''],
    ].filter(([, v]) => v);
    if (kv.length) {
      parts.push(`<div class="d-kv">${kv.map(([k, v]) =>
        `<div><span>${esc(k)}</span><b>${esc(v)}</b></div>`).join('')}</div>`);
    }

    // 原文 / 发给上游
    const orig = e.dialog || '';
    const up = e.masked_dialog || '';
    if (up) {
      parts.push(`<div class="cmp2">
        <div class="cmp2-col">
          <div class="cmp2-head"><span class="cmp2-title cmp2-title-orig">原文（客户端发出）</span></div>
          <pre class="cmp2-pre">${highlight(orig, needles)}</pre>
        </div>
        <div class="cmp2-col">
          <div class="cmp2-head"><span class="cmp2-title cmp2-title-up">发给上游（已脱敏）</span></div>
          <pre class="cmp2-pre">${highlight(up, [])}</pre>
        </div>
      </div>`);
    } else if (orig) {
      // 老事件没有 masked_dialog：按命中明细推算，并如实标注
      const derived = deriveMasked(orig, items);
      const title = type === 'MASK' ? '原文（客户端发出）'
        : type === 'RESTORE' ? '助手回复（还原后）' : '正文';
      if (derived !== orig) {
        parts.push(`<div class="cmp2">
          <div class="cmp2-col">
            <div class="cmp2-head"><span class="cmp2-title cmp2-title-orig">${esc(title)}</span></div>
            <pre class="cmp2-pre">${highlight(orig, needles)}</pre>
          </div>
          <div class="cmp2-col">
            <div class="cmp2-head"><span class="cmp2-title cmp2-title-up">发给上游（按命中明细推算）</span></div>
            <pre class="cmp2-pre">${highlight(derived, [])}</pre>
          </div>
        </div>`);
      } else {
        parts.push(`<div class="detail-section"><div class="detail-title">${esc(title)}</div>
          <pre class="cmp2-pre">${highlight(orig, needles)}</pre></div>`);
      }
    }

    if (items.length) {
      parts.push(`<div class="detail-section">
        <div class="detail-title">命中明细 · ${items.length}</div>
        <table class="cmp cmp-items"><thead><tr>
          <th>类型</th><th>原文</th><th>占位符</th><th>长度 / 摘要</th>
        </tr></thead><tbody>${items.map(it => {
          const src = it.original
            ? esc(it.original)
            : (it.preview
                ? `<span class="item-redacted hint" title="凭据类不存明文，只留打码预览与 sha256 摘要">${esc(it.preview)}</span>`
                : '<span class="hint">—</span>');
          const meta = [
            it.length ? esc(it.length) + ' 位' : '',
            it.digest ? 'sha256:' + esc(String(it.digest).slice(0, 12)) : '',
          ].filter(Boolean).join(' · ');
          return `<tr>
            <td class="mono">${it.cred ? '🔒 ' : ''}${esc(it.label)}</td>
            <td class="mono cmp-orig">${src}</td>
            <td class="mono cmp-tok">${esc(it.tok || it.token || '—')}</td>
            <td class="mono hint">${meta || '—'}</td>
          </tr>`;
        }).join('')}</tbody></table></div>`);
    }

    if ((e.unresolved_samples || []).length) {
      parts.push(`<div class="note warn">未还原占位符：<span class="mono">${e.unresolved_samples.map(esc).join('、')}</span></div>`);
    }
    if (e.message || e.reason) {
      parts.push(`<div class="note warn">${esc(e.message || e.reason)}</div>`);
    }
    return parts.join('');
  }

  async function loadLogs() {
    const q = log.q.trim();
    const url = `/logs?limit=${log.limit}&offset=${log.offset}`
      + (log.type ? `&event_type=${encodeURIComponent(log.type)}` : '')
      + (q ? `&q=${encodeURIComponent(q)}` : '');
    const data = await api(url);
    log.rows = data.events || [];
    log.total = data.total == null ? log.rows.length : data.total;

    $('logList').innerHTML = log.rows.length
      ? log.rows.map(logRowHtml).join('')
      : emptyBox('没有符合条件的事件');

    const pages = Math.max(1, Math.ceil(log.total / log.limit));
    const page = Math.floor(log.offset / log.limit) + 1;
    $('logMeta').textContent = `共 ${log.total} 条 · 第 ${page}/${pages} 页`
      + (log.auto ? ' · 自动刷新中' : '');
    $('logPrev').disabled = log.offset <= 0;
    $('logNext').disabled = log.offset + log.limit >= log.total;

    // 选中项：优先保留原选择，否则自动选第一条
    const keep = log.rows.some(e => e.id === log.sel);
    if (!keep) log.sel = log.rows.length ? log.rows[0].id : null;
    document.querySelectorAll('#logList .lrow').forEach(el => {
      const on = Number(el.dataset.logId) === log.sel;
      el.classList.toggle('active', on);
      el.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    if (log.sel == null) { $('logDetail').innerHTML = emptyBox('左侧选择一条事件'); return; }
    await showLogDetail(log.sel);
  }
  loaders.logs = loadLogs;

  async function showLogDetail(id) {
    $('logDetail').innerHTML = emptyBox('加载中…');
    try {
      const d = await api('/logs/detail?id=' + encodeURIComponent(id));
      if (log.sel !== id) return; // 期间已切到别的行
      $('logDetail').innerHTML = logDetailHtml(d.event || d);
    } catch (e) {
      $('logDetail').innerHTML = `<div class="note warn">详情加载失败：${esc(e.message)}</div>`;
    }
  }

  $('logList').addEventListener('click', ev => {
    const row = ev.target.closest('.lrow');
    if (!row) return;
    const id = Number(row.dataset.logId);
    if (id === log.sel) return;
    log.sel = id;
    document.querySelectorAll('#logList .lrow').forEach(el => {
      const on = Number(el.dataset.logId) === id;
      el.classList.toggle('active', on);
      el.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    showLogDetail(id);
  });
  $('logType').addEventListener('change', () => {
    log.type = $('logType').value; log.offset = 0; log.sel = null;
    loadLogs().catch(e => toast(e.message, true));
  });
  let logSearchTimer = null;
  $('logSearch').addEventListener('input', () => {
    clearTimeout(logSearchTimer);
    logSearchTimer = setTimeout(() => {
      log.q = $('logSearch').value; log.offset = 0; log.sel = null;
      loadLogs().catch(e => toast(e.message, true));
    }, 250);
  });
  $('logAuto').addEventListener('change', ev => {
    if (ev.target.checked) { startLogAuto(); toast('已开启自动刷新（5s）'); }
    else { stopLogAuto(); toast('已关闭自动刷新'); }
  });
  $('logRefresh').addEventListener('click', () => loadLogs().catch(e => toast(e.message, true)));
  $('logPrev').addEventListener('click', () => {
    log.offset = Math.max(0, log.offset - log.limit); log.sel = null;
    loadLogs().catch(e => toast(e.message, true));
  });
  $('logNext').addEventListener('click', () => {
    if (log.offset + log.limit >= log.total) return;
    log.offset += log.limit; log.sel = null;
    loadLogs().catch(e => toast(e.message, true));
  });
  $('logClear').addEventListener('click', () => {
    if (!confirm('清空事件日志？（统计摘要保留）')) return;
    api('/logs/clear', { method: 'POST' }).then(() => {
      toast('已清空'); log.offset = 0; log.sel = null; return loadLogs();
    }).catch(e => toast(e.message, true));
  });

  /* ==================== 审计（主从双栏） ==================== */
  const audit = { sev: '', q: '', rows: [], sel: null };

  function auditRowHtml(a) {
    return `<button class="lrow ${audit.sel === a.id ? 'active' : ''}" data-audit-id="${a.id}" role="option"
              aria-selected="${audit.sel === a.id ? 'true' : 'false'}">
        <span class="lrow-top">
          <span class="lrow-time">${esc(fmtTime(a.ts))}</span>
          <span class="sev sev-${esc(a.severity)}">${esc(a.severity)}</span>
        </span>
        <span class="lrow-sub"><span class="lrow-path">${esc(a.signal_type)}</span></span>
        <span class="lrow-evidence">${esc(a.evidence || '')}</span>
      </button>`;
  }

  function auditDetailHtml(a) {
    const kv = [
      ['时间', fmtTs(a.ts)],
      ['主机', a.host || ''],
      ['方法 / 路径', `${a.method || ''} ${a.path || ''}`.trim()],
      ['会话', a.sid || ''],
    ].filter(([, v]) => v);
    return `<header class="d-head">
        <div class="d-head-main">
          <span class="sev sev-${esc(a.severity)}">${esc(a.severity)}</span>
          <span class="mono d-path">${esc(a.signal_type)}</span>
        </div>
      </header>
      <div class="d-kv">${kv.map(([k, v]) =>
        `<div><span>${esc(k)}</span><b>${esc(v)}</b></div>`).join('')}</div>
      <div class="detail-section">
        <div class="detail-title">证据</div>
        <pre class="cmp2-pre">${highlight(a.evidence || '—', [])}</pre>
      </div>`;
  }

  async function loadAudit() {
    const data = await api('/audit/events?limit=500');
    audit.rows = data.events || [];
    renderAudit();
  }
  loaders.audit = loadAudit;

  function renderAudit() {
    const q = audit.q.trim().toLowerCase();
    const rows = audit.rows.filter(a => {
      if (audit.sev && a.severity !== audit.sev) return false;
      if (q) {
        const hay = `${a.signal_type} ${a.evidence || ''} ${a.path || ''} ${a.host || ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    $('auditList').innerHTML = rows.length
      ? rows.map(auditRowHtml).join('')
      : emptyBox(audit.rows.length ? '没有符合筛选条件的审计' : '暂无审计事件');
    $('auditMeta').textContent = audit.rows.length
      ? `已加载最近 ${audit.rows.length} 条${rows.length !== audit.rows.length ? ` · 命中 ${rows.length}` : ''}`
      : '';
    if (!rows.length) { audit.sel = null; $('auditDetail').innerHTML = emptyBox('左侧选择一条审计'); return; }
    if (!rows.some(a => a.id === audit.sel)) audit.sel = rows[0].id;
    const cur = rows.find(a => a.id === audit.sel) || audit.rows.find(a => a.id === audit.sel);
    if (cur) $('auditDetail').innerHTML = auditDetailHtml(cur);
  }

  $('auditList').addEventListener('click', ev => {
    const row = ev.target.closest('.lrow');
    if (!row) return;
    audit.sel = Number(row.dataset.auditId);
    renderAudit();
  });
  $('auditSev').addEventListener('change', () => {
    audit.sev = $('auditSev').value;
    audit.sel = null;
    renderAudit();
  });
  let auditSearchTimer = null;
  $('auditSearch').addEventListener('input', () => {
    clearTimeout(auditSearchTimer);
    auditSearchTimer = setTimeout(() => {
      audit.q = $('auditSearch').value;
      renderAudit();
    }, 200);
  });
  $('auditRefresh').addEventListener('click', () => loadAudit().catch(e => toast(e.message, true)));
  $('auditClear').addEventListener('click', () => {
    if (!confirm('清空审计事件？')) return;
    api('/audit/clear', { method: 'POST' }).then(() => {
      toast('已清空'); audit.sel = null; return loadAudit();
    }).catch(e => toast(e.message, true));
  });

  /* ==================== 脱敏测试 ==================== */
  const TEST_PRESETS = {
    basic: '我是张三，手机 13800138000，邮箱 zhangsan@example.com，身份证 110101199003078675。',
    cred: '数据库连接 postgres://admin:Sup3rSecret@10.0.0.5:5432/prod\nAPI Key: sk-abcdefghijklmnopqrstuvwxyz012345',
    custom: '请确认 ACME 项目的交付时间，以及第二大股东的意见。',
    mixed: '你好，我是李四。电话 13900139000，公司内网 192.168.1.100，' +
           '工号 E12345，密钥 sk-abcdefghijklmnopqrstuvwxyz012345，邮箱 li@example.com。',
  };

  async function runMaskTest() {
    const text = $('testInput').value;
    if (!text.trim()) return toast('请输入待测文本', true);
    const body = {
      text,
      mode: $('testMode').value,
      protocol: $('testProtocol').value,
      model: $('testModel').value.trim() || 'gpt-4o',
    };
    const btn = $('btnRunTest');
    btn.disabled = true;
    btn.textContent = '测试中…';
    try {
      const r = await api('/mask/test', { method: 'POST', body: JSON.stringify(body) });
      const items = r.items || [];
      const needles = items.map(it => it.original).filter(Boolean);
      $('testMasked').innerHTML = highlight(r.masked, []);
      $('testRestored').innerHTML = highlight(r.restored, needles);
      $('testSummary').textContent =
        `命中 ${r.count} 项 · ${r.elapsed_ms}ms · 临时映射已销毁（未落库）`;
      $('testItems').innerHTML = items.length
        ? items.map(it => `<tr>
            <td class="mono">${it.cred ? '🔒 ' : ''}${esc(it.label)}</td>
            <td class="mono cmp-orig">${esc(it.original || it.preview || '—')}</td>
            <td class="mono cmp-tok">${esc(it.tok || it.token || '—')}</td>
            <td class="mono hint">${it.length != null ? esc(it.length) + ' 位' : '—'}</td>
          </tr>`).join('')
        : '<tr><td colspan="4" class="empty">未命中任何规则</td></tr>';
      $('testItemsWrap').hidden = !items.length;
      $('testResult').hidden = false;
    } catch (e) {
      toast('测试失败：' + e.message, true);
    } finally {
      btn.disabled = false;
      btn.textContent = '运行测试';
    }
  }
  loaders.test = async () => {};

  $('btnRunTest').addEventListener('click', runMaskTest);
  $('testInput').addEventListener('keydown', ev => {
    if ((ev.metaKey || ev.ctrlKey) && ev.key === 'Enter') { ev.preventDefault(); runMaskTest(); }
  });
  document.querySelectorAll('[data-preset]').forEach(b => b.addEventListener('click', () => {
    $('testInput').value = TEST_PRESETS[b.dataset.preset] || '';
    runMaskTest();
  }));
  $('btnCopyMasked').addEventListener('click', () => copyFrom($('testMasked'), $('btnCopyMasked')));
  $('btnCopyRestored').addEventListener('click', () => copyFrom($('testRestored'), $('btnCopyRestored')));

  /* ==================== 设置 ==================== */
  async function loadSettings() {
    const cfg = await api('/config');
    $('upstreamTarget').value = cfg.upstream.target || '';
    $('serverPort').value = cfg.server.port;
    $('serverBind').value = cfg.server.bind;
    $('failClosed').checked = !!cfg.fail_closed;
    $('responseScan').checked = !!cfg.response_scan;
    $('streamResponse').checked = !!cfg.stream_response;
    $('cmdMode').value = cfg.command_block.mode || 'observe';
    $('retentionDays').value = cfg.log_retention_days;
    $('panelToken').value = cfg.panel_token || '';
    $('saveMsg').textContent = '';
  }
  loaders.settings = loadSettings;

  $('btnSave').addEventListener('click', async () => {
    try {
      const cfg = await api('/config');
      cfg.upstream.target = $('upstreamTarget').value.trim();
      cfg.server.port = parseInt($('serverPort').value, 10) || cfg.server.port;
      cfg.server.bind = $('serverBind').value.trim() || cfg.server.bind;
      cfg.fail_closed = $('failClosed').checked;
      cfg.response_scan = $('responseScan').checked;
      cfg.stream_response = $('streamResponse').checked;
      cfg.command_block.mode = $('cmdMode').value;
      cfg.log_retention_days = parseInt($('retentionDays').value, 10) || 7;
      const newTok = $('panelToken').value.trim();
      if (newTok && newTok !== cfg.panel_token) cfg.panel_token = newTok;
      const r = await api('/config', { method: 'POST', body: JSON.stringify(cfg) });
      const w = (r.warnings || []);
      toast('已保存' + (w.length ? '（' + w.join('；') + '）' : ''), w.length > 0);
      if ($('panelToken').value.trim() !== cfg.panel_token) {
        TOKEN = $('panelToken').value.trim();
        localStorage.setItem(LS_TOKEN, TOKEN);
      }
      $('saveMsg').textContent = '已保存 ' + new Date().toLocaleTimeString();
    } catch (e) { toast('保存失败：' + e.message, true); }
  });

  $('btnRotateToken').addEventListener('click', () => {
    const CH = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
    const a = new Uint8Array(24);
    crypto.getRandomValues(a);
    $('panelToken').value = Array.from(a).map(b => CH[b % CH.length]).join('');
    toast('已生成新令牌，记得点「保存配置」');
  });

  // 令牌默认遮蔽显示（防肩窥 / 投屏泄露），需要复制时再点「显示」
  $('btnToggleToken').addEventListener('click', () => {
    const el = $('panelToken');
    const show = el.type === 'password';
    el.type = show ? 'text' : 'password';
    const btn = $('btnToggleToken');
    btn.textContent = show ? '隐藏' : '显示';
    btn.setAttribute('aria-label', show ? '隐藏令牌' : '显示令牌');
  });

  /* ==================== 启动 ==================== */
  if (TOKEN) {
    api('/status').then(() => {
      enterApp();
      switchPage(hashPage() || 'dashboard');
    }).catch(() => showLogin());
  } else {
    showLogin();
  }
  setInterval(() => {
    if (!TOKEN || currentPage !== 'dashboard') return;
    if (document.hidden) return; // 页面不可见时不轮询，省掉无谓请求
    loadDashboard().catch(() => {});
  }, 6000);
})();
