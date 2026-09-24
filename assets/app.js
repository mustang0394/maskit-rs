/* Maskit-RS 控制台（原生 JS，无构建步骤） */
(function () {
  'use strict';

  const API = '/console/api';
  const LS_TOKEN = 'maskit_token';
  const LS_THEME = 'maskit_theme';
  let TOKEN = localStorage.getItem(LS_TOKEN) || '';

  /* ---------------- 主题 ---------------- */
  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(LS_THEME, theme);
    const icon = document.getElementById('themeIcon');
    if (icon) icon.textContent = theme === 'dark' ? '☀' : '☾';
    const btn = document.getElementById('themeToggle');
    if (btn) btn.title = theme === 'dark' ? '切换到浅色主题' : '切换到深色主题';
  }
  applyTheme(localStorage.getItem(LS_THEME) || 'dark');

  /* ---------------- 工具 ---------------- */
  function $(id) { return document.getElementById(id); }
  function esc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }
  function fmtTs(ts) {
    if (!ts) return '';
    const d = new Date(ts * 1000);
    const p = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }
  let toastTimer = null;
  function toast(msg, isErr) {
    const el = $('toast');
    el.textContent = msg;
    el.className = 'toast' + (isErr ? ' err' : '');
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, 3200);
  }

  /* ---------------- API ---------------- */
  async function api(path, opts) {
    const res = await fetch(API + path, Object.assign({
      headers: Object.assign({ 'Content-Type': 'application/json' },
        TOKEN ? { Authorization: 'Bearer ' + TOKEN } : {}),
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
  }

  /* ---------------- 登录 ---------------- */
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
      await api('/status');                    // 验证令牌
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
    showLogin();
  });

  $('themeToggle').addEventListener('click', () => {
    const cur = document.documentElement.getAttribute('data-theme');
    applyTheme(cur === 'dark' ? 'light' : 'dark');
  });

  /* ---------------- 页面切换 ---------------- */
  const loaders = {};
  function switchPage(name) {
    document.querySelectorAll('.tab').forEach(t =>
      t.classList.toggle('active', t.dataset.page === name));
    document.querySelectorAll('.page').forEach(p =>
      p.classList.toggle('active', p.id === 'page-' + name));
    if (loaders[name]) loaders[name]().catch(e => toast(e.message, true));
  }
  $('tabs').addEventListener('click', ev => {
    const t = ev.target.closest('.tab');
    if (t) switchPage(t.dataset.page);
  });

  /* ---------------- 概览 ---------------- */
  async function loadDashboard() {
    const [status, today] = await Promise.all([api('/status'), api('/stats/today')]);
    const c = status.counters || {};
    $('statCards').innerHTML = [
      ['请求总数', c.requests], ['已脱敏', c.masked], ['已还原', c.restored],
      ['已阻断', c.blocked], ['透传', c.bypassed], ['错误', c.errors],
      ['今日 token', today.tokens_total],
    ].map(([k, v]) =>
      `<div class="card"><div class="v">${v == null ? 0 : v}</div><div class="k">${k}</div></div>`).join('');

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
  $('btnPause').addEventListener('click', () =>
    api('/proxy/pause', { method: 'POST' }).then(() => { toast('已暂停脱敏（纯透传）'); loadDashboard(); })
       .catch(e => toast(e.message, true)));
  $('btnResume').addEventListener('click', () =>
    api('/proxy/resume', { method: 'POST' }).then(() => { toast('已恢复脱敏'); loadDashboard(); })
       .catch(e => toast(e.message, true)));

  /* ---------------- 规则 ---------------- */
  const RULE_LABELS = {
    API_KEY: 'API Key / 密钥前缀', ACCESS_KEY: '云厂商 AccessKey', CARD: '银行卡（Luhn 校验）',
    CONNSTR: '连接串密码', EMAIL: '邮箱地址', HKID: '港澳通行证', IBAN: 'IBAN 银行账号',
    IDCARD: '身份证（15/18 位）', IP_INTERNAL: '内网 IP（10.x / 172.16-31）',
    IP_PRIVATE: '内网 IP（192.168 / 169.254 / 100.64）', IP_PUBLIC: '公网 IP',
    IPV6_PRIVATE: 'IPv6 私网（fe80:: / fc00::）', JWT: 'JWT 令牌', LANDLINE: '固定电话',
    MAC: 'MAC 地址', PHONE: '手机号', PLATE: '车牌号', PRIVATE_KEY: 'PEM 私钥',
    SECRET: '键值对凭据（password=…）', TOKEN: 'Bearer Token', USCC: '统一社会信用代码',
  };
  const RULE_DEFAULT_ON = ['API_KEY', 'CARD', 'CONNSTR', 'EMAIL', 'IDCARD', 'LANDLINE', 'PHONE'];

  async function loadRules() {
    const cfg = await api('/config');
    const rules = cfg.mask.builtin_rules || {};
    const keys = Object.keys(rules).sort();

    $('ruleToggles').innerHTML = keys.map(k => {
      const name = RULE_LABELS[k] || k;
      const full = `${name}（${k}）`;
      return `<label class="rule-item ${rules[k] ? 'on' : ''}" title="${esc(full)}">
        <input type="checkbox" data-rule="${esc(k)}" ${rules[k] ? 'checked' : ''}/>
        <span class="rule-text">
          <span class="rule-name">${esc(name)}</span>
          <span class="rule-key">${esc(k)}</span>
        </span>
      </label>`;
    }).join('');

    const onCount = keys.filter(k => rules[k]).length;
    $('ruleSummary').textContent = `已开启 ${onCount} / ${keys.length}`;

    // 事件委托：单个开关变更立即保存
    $('ruleToggles').addEventListener('change', async ev => {
      const cb = ev.target.closest('input[data-rule]');
      if (!cb) return;
      const item = cb.closest('.rule-item');
      item.classList.toggle('on', cb.checked);
      try {
        await api('/config/patch', {
          method: 'POST',
          body: JSON.stringify({ path: 'mask.builtin_rules.' + cb.dataset.rule, value: cb.checked }),
        });
        const cfg2 = await api('/config');
        const r2 = cfg2.mask.builtin_rules || {};
        const n = Object.values(r2).filter(Boolean).length;
        $('ruleSummary').textContent = `已开启 ${n} / ${Object.keys(r2).length}`;
        toast(`${cb.dataset.rule} 已${cb.checked ? '开启' : '关闭'}`);
      } catch (e) {
        cb.checked = !cb.checked;
        item.classList.toggle('on', cb.checked);
        toast('保存失败：' + e.message, true);
      }
    });

    // 自定义词：按分类分组展示
    const words = cfg.mask.custom_words || {};
    const groups = new Map();
    for (const [w, l] of Object.entries(words)) {
      const key = l || 'TERM';
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(w);
    }
    // 分类补全：已用过的分类直接选
    $('labelOptions').innerHTML = [...groups.keys()]
      .sort()
      .map(l => `<option value="${esc(l)}"></option>`).join('');
    // 占位符标签只留 ASCII：中文分类会退化成 TERM，提前告知避免误解
    const pendingLabel = $('newLabel').value.trim();
    const tokLabel = safeLabel(pendingLabel);
    $('labelHint').textContent = pendingLabel && tokLabel !== pendingLabel
      ? `占位符前缀将使用 ${tokLabel}（${pendingLabel} 含非 ASCII 字符，会被剔除）`
      : '';
    $('wordList').innerHTML = groups.size
      ? [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([label, ws]) => `
          <div class="word-group">
            <span class="word-group-name">${esc(label)}
              <span class="tok">{{${esc(safeLabel(label))}_xxxxxx}}</span>
            </span>
            ${ws.sort().map(w => `<span class="chip" title="${esc(w)}">
              <span class="chip-text">${esc(w)}</span>
              <button data-del-word="${esc(w)}" aria-label="删除">×</button>
            </span>`).join('')}
          </div>`).join('')
      : '<span class="hint">暂无自定义敏感词</span>';

    // 前缀
    const prefixes = cfg.mask.secret_prefixes || [];
    $('prefixList').innerHTML = prefixes.length
      ? prefixes.map(p => `<span class="chip"><span class="chip-text mono">${esc(p)}</span>
            <button data-del-prefix="${esc(p)}" aria-label="删除">×</button></span>`).join('')
      : '<span class="hint">未配置前缀规则</span>';
  }
  loaders.rules = loadRules;

  // 占位符标签 ASCII 化（与服务端 safe_label 一致）
  function safeLabel(label) {
    const s = String(label || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12);
    return s || 'TERM';
  }
  // 多词切分：换行 / 逗号 / 顿号 / 分号 / 空白
  function splitWords(text) {
    return [...new Set(
      String(text || '').split(/[\n\r,，、;；\s]+/)
        .map(s => s.trim()).filter(Boolean)
    )];
  }

  $('btnAddWord').addEventListener('click', async () => {
    const list = splitWords($('newWords').value);
    const label = $('newLabel').value.trim() || 'TERM';
    if (!list.length) return toast('请输入至少一个敏感词', true);
    if (list.some(w => w.length > 200)) return toast('单个敏感词不能超过 200 字符', true);
    try {
      const cfg = await api('/config');
      const next = Object.assign({}, cfg.mask.custom_words);
      // 整个词表一次 patch：避免 N 次往返，也避开读-改-写竞态
      const added = [];
      for (const w of list) {
        if (!Object.prototype.hasOwnProperty.call(next, w)) added.push(w);
        next[w] = label;
      }
      await api('/config/patch', {
        method: 'POST', body: JSON.stringify({ segs: ['mask', 'custom_words'], value: next })
      });
      $('newWords').value = '';
      toast(added.length
        ? `已添加 ${added.length} 个词到「${label}」${list.length > added.length ? `（${list.length - added.length} 个已存在，已改分类）` : ''}`
        : `已更新 ${list.length} 个词的分类为「${label}」`);
      loadRules();
    } catch (e) { toast('保存失败：' + e.message, true); }
  });

  $('btnAddPrefix').addEventListener('click', async () => {
    const p = $('newPrefix').value.trim();
    if (!p) return toast('请输入前缀', true);
    try {
      const cfg = await api('/config');
      const list = (cfg.mask.secret_prefixes || []).slice();
      if (list.includes(p)) { toast('该前缀已存在', true); return; }
      list.push(p);
      await api('/config/patch', {
        method: 'POST', body: JSON.stringify({ path: 'mask.secret_prefixes', value: list }),
      });
      $('newPrefix').value = '';
      toast('已添加前缀 ' + p);
      loadRules();
    } catch (e) { toast(e.message, true); }
  });

  $('btnRulesDefault').addEventListener('click', async () => {
    if (!confirm('把所有内置规则恢复为默认开关状态？')) return;
    try {
      const cfg = await api('/config');
      const cur = cfg.mask.builtin_rules || {};
      const next = {};
      Object.keys(cur).forEach(k => { next[k] = RULE_DEFAULT_ON.includes(k); });
      await api('/config/patch', { method: 'POST', body: JSON.stringify({ path: 'mask.builtin_rules', value: next }) });
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
      await api('/config/patch', { method: 'POST', body: JSON.stringify({ path: 'mask.builtin_rules', value: next }) });
      toast('已开启全部规则');
      loadRules();
    } catch (e) { toast(e.message, true); }
  });

  $('wordList').addEventListener('click', async ev => {
    const b = ev.target.closest('button[data-del-word]');
    if (!b) return;
    const w = b.dataset.delWord;
    try {
      // 用 segs 而非点分 path：词含 '.' 时点分会被切成多段而写错位置
      await api('/config/patch', {
        method: 'POST',
        body: JSON.stringify({ segs: ['mask', 'custom_words', w], value: null })
      });
      toast('已删除「' + w + '」');
      loadRules();
    } catch (e) { toast('删除失败：' + e.message, true); }
  });

  $('prefixList').addEventListener('click', async ev => {
    const b = ev.target.closest('button[data-del-prefix]');
    if (!b) return;
    const p = b.dataset.delPrefix;
    try {
      const cfg = await api('/config');
      const list = (cfg.mask.secret_prefixes || []).filter(x => x !== p);
      await api('/config/patch', { method: 'POST', body: JSON.stringify({ path: 'mask.secret_prefixes', value: list }) });
      toast('已删除前缀 ' + p);
      loadRules();
    } catch (e) { toast(e.message, true); }
  });

  /* ---------------- 日志 ---------------- */
  let logRows = [];        // 列表数据缓存，供详情展开复用
  let openLogId = null;    // 当前展开的事件 id

  async function loadLogs() {
    const f = $('logFilter').value;
    const data = await api('/logs?limit=200' + (f ? '&event_type=' + f : ''));
    logRows = data.events || [];
    $('logList').innerHTML = logRows.length
      ? logRows.map(renderLogRow).join('')
      : '<tr><td colspan="7" class="empty">暂无事件</td></tr>';
  }
  loaders.logs = loadLogs;

  /** 凭据类：original 恒空（红线），退而显示打码预览 + 摘要 */
  function itemSource(it) {
    if (it.original) return esc(it.original);
    if (it.preview) return `<span class="item-redacted" title="凭据类不存明文">${esc(it.preview)}</span>`;
    return '<span class="hint">—</span>';
  }

  /** 单条命中：原文 → 占位符（这就是「加密后的字符串」） */
  function renderItem(it) {
    // 后端序列化名是 `tok`（serde rename），不是 `token`
    const tok = it.tok || it.token || '';
    const tail = [
      it.length ? `<span class="hint">${it.length} 位</span>` : '',
      it.digest ? `<span class="hint mono" title="sha256 摘要">#${esc(String(it.digest).slice(0, 8))}</span>` : '',
    ].filter(Boolean).join(' ');
    return `<div class="item">
      <span class="item-label">${it.cred ? '<span class="lock" title="凭据类">🔒</span>' : ''}${esc(it.label)}</span>
      <span class="item-src mono">${itemSource(it)}</span>
      <span class="item-arrow">→</span>
      <span class="item-tok mono">${tok ? esc(tok) : '<span class="hint">—</span>'}</span>
      ${tail ? `<span class="item-meta">${tail}</span>` : ''}
    </div>`;
  }

  function renderLogRow(e) {
    const t = String(e.type || '');
    const items = e.items || [];
    // 统计：count=命中数 restored=还原数，其余为异常计数
    const stat = [];
    if (e.count) stat.push(`<span class="st st-mask">脱敏 ${e.count}</span>`);
    if (e.restored) stat.push(`<span class="st st-restore">还原 ${e.restored}</span>`);
    if (e.unresolved) stat.push(`<span class="st st-warn">未还原 ${e.unresolved}</span>`);
    if (e.degraded) stat.push(`<span class="st st-deg">容错 ${e.degraded}</span>`);
    const flags = [];
    if (e.stream_mode) {
      const actual = e.stream_actual || 'whole';
      const bad = actual !== e.stream_mode;
      flags.push(`<span class="hint${bad ? ' st-warn' : ''}" title="声明流式 ${esc(e.stream_mode)} / 实际 ${esc(actual)}">${bad ? '流式不符 ' : ''}${esc(e.stream_mode)}</span>`);
    }
    if (e.unknown_shape) flags.push('<span class="st-warn">未知形态</span>');
    if (e.status >= 400) flags.push(`<span class="st-warn">${e.status}</span>`);
    if (e.req_bytes) flags.push(`<span class="hint">↑${e.req_bytes}</span>`);

    return `<tr class="log-row${openLogId === e.id ? ' open' : ''}" data-log-id="${e.id}">
      <td class="col-time mono">${esc(fmtTs(e.ts))}</td>
      <td class="col-type"><span class="badge ${esc(t)}">${esc(t)}</span></td>
      <td class="col-req"><span class="path mono">${esc(e.method)} ${esc(e.path)}</span>
        ${flags.length ? `<div class="row-flags">${flags.join(' ')}</div>` : ''}</td>
      <td class="col-model mono">${esc(e.model || '—')}</td>
      <td class="col-stat">${stat.join(' ') || '<span class="hint">—</span>'}</td>
      <td class="col-items">${items.length
          ? `<div class="item-list">${items.map(renderItem).join('')}</div>`
          : `<span class="hint">${esc(e.reason || e.message || '无命中')}</span>`}</td>
      <td class="col-ms mono">${e.mask_ms != null ? esc(Number(e.mask_ms).toFixed(1)) + 'ms' : '—'}</td>
    </tr>
    <tr class="log-detail" data-detail-for="${e.id}" hidden><td colspan="7"><div class="detail-box">加载中…</div></td></tr>`;
  }

  // 点行展开详情（回源 /logs/detail，与 Python 的详情弹窗同源）
  $('logList').addEventListener('click', async ev => {
    const tr = ev.target.closest('tr.log-row');
    if (!tr) return;
    const id = Number(tr.dataset.logId);
    const box = document.querySelector(`tr.log-detail[data-detail-for="${id}"] td`);
    if (openLogId === id) {           // 再次点击收起
      box.parentElement.hidden = true;
      tr.classList.remove('open');
      openLogId = null;
      return;
    }
    // 先把之前展开的收起来
    if (openLogId !== null) {
      const prev = document.querySelector(`tr.log-detail[data-detail-for="${openLogId}"]`);
      if (prev) prev.hidden = true;
      const prevRow = document.querySelector(`tr.log-row[data-log-id="${openLogId}"]`);
      if (prevRow) prevRow.classList.remove('open');
    }
    openLogId = id;
    tr.classList.add('open');
    box.parentElement.hidden = false;
    box.innerHTML = '<div class="detail-box hint">加载中…</div>';
    try {
      const d = await api('/logs/detail?id=' + id);
      box.innerHTML = renderLogDetail(d);
    } catch (e) {
      box.innerHTML = `<div class="detail-box hint">详情加载失败：${esc(e.message)}</div>`;
    }
  });

  function renderLogDetail(d) {
    const e = d.event || d;
    const parts = [];
    if (e.message || e.reason) {
      parts.push(`<div class="detail-note">${esc(e.message || e.reason)}</div>`);
    }
    if ((e.unresolved_samples || []).length) {
      parts.push(`<div class="detail-note">未还原占位符：<span class="mono">${e.unresolved_samples.map(esc).join('、')}</span></div>`);
    }
    if ((e.items || []).length) {
      parts.push(`<div class="detail-section">对照明细
        <table class="cmp"><thead><tr>
          <th>类型</th><th>原文</th><th>预览</th><th>占位符（加密后）</th><th>摘要 / 长度</th>
        </tr></thead><tbody>${e.items.map(it => `<tr>
          <td class="mono">${it.cred ? '🔒 ' : ''}${esc(it.label)}</td>
          <td class="mono cmp-orig">${it.original ? esc(it.original) : '<span class="hint">不存明文</span>'}</td>
          <td class="mono hint">${esc(it.preview || '—')}</td>
          <td class="mono cmp-tok">${esc(it.tok || it.token || '—')}</td>
          <td class="mono hint">${it.digest ? 'sha256:' + esc(String(it.digest).slice(0, 12)) : (it.hash || '—')}${it.length ? ' · ' + it.length + '位' : ''}</td>
        </tr>`).join('')}</tbody></table></div>`);
    }
    if (e.dialog) {
      parts.push(`<div class="detail-section">${e.type === 'MASK' ? '用户消息原文' : '助手回复原文'}
        <pre class="detail-pre">${esc(e.dialog)}</pre></div>`);
    }
    if (!parts.length) parts.push('<div class="detail-box hint">无更多详情</div>');
    return parts.join('');
  }
  $('btnRefreshLogs').addEventListener('click', () => loadLogs().catch(e => toast(e.message, true)));
  $('logFilter').addEventListener('change', () => loadLogs().catch(e => toast(e.message, true)));
  $('btnClearLogs').addEventListener('click', () => {
    if (!confirm('清空事件日志？（统计摘要保留）')) return;
    api('/logs/clear', { method: 'POST' }).then(() => { toast('已清空'); loadLogs(); })
       .catch(e => toast(e.message, true));
  });

  /* ---------------- 审计 ---------------- */
  async function loadAudit() {
    const data = await api('/audit/events?limit=200');
    const evs = data.events || [];
    $('auditList').innerHTML = evs.length ? evs.map(a => `<tr class="audit-row">
      <td class="col-time mono">${esc(fmtTs(a.ts))}</td>
      <td class="col-sev"><span class="sev sev-${esc(a.severity)}">${esc(a.severity)}</span></td>
      <td class="col-signal mono">${esc(a.signal_type)}</td>
      <td class="col-evidence">${esc(a.evidence || '—')}</td>
      <td class="col-req"><span class="path mono">${esc(a.method || '')} ${esc(a.path || '')}</span></td>
    </tr>`).join('') : '<tr><td colspan="5" class="empty">暂无审计事件</td></tr>';
  }
  loaders.audit = loadAudit;
  $('btnRefreshAudit').addEventListener('click', () => loadAudit().catch(e => toast(e.message, true)));
  $('btnClearAudit').addEventListener('click', () => {
    if (!confirm('清空审计事件？')) return;
    api('/audit/clear', { method: 'POST' }).then(() => { toast('已清空'); loadAudit(); })
       .catch(e => toast(e.message, true));
  });

  /* ---------------- 设置 ---------------- */
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
  }
  loaders.settings = loadSettings;

  $('btnSave').addEventListener('click', async () => {
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
    try {
      const r = await api('/config', { method: 'POST', body: JSON.stringify(cfg) });
      const w = (r.warnings || []);
      toast('已保存' + (w.length ? '（' + w.join('；') + '）' : ''), w.length > 0);
      if ($('panelToken').value.trim() !== cfg.panel_token) {
        TOKEN = $('panelToken').value.trim();
        localStorage.setItem(LS_TOKEN, TOKEN);
      }
    } catch (e) { toast('保存失败：' + e.message, true); }
  });

  $('btnRotateToken').addEventListener('click', () => {
    const CH = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
    const a = new Uint8Array(24);
    crypto.getRandomValues(a);
    $('panelToken').value = Array.from(a).map(b => CH[b % CH.length]).join('');
    toast('已生成新令牌，记得点「保存配置」');
  });

  /* ---------------- 启动 ---------------- */
  if (TOKEN) {
    api('/status')
      .then(enterApp)
      .catch(() => showLogin());
  } else {
    showLogin();
  }
  setInterval(() => { if (TOKEN) loadDashboard().catch(() => {}); }, 6000);
})();
