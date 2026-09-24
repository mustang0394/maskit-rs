/* Maskit-RS 控制台（原生 JS，无构建步骤） */
(function () {
  'use strict';

  const API = '/console/api';
  let TOKEN = localStorage.getItem('maskit_token') || '';

  function authHeaders(extra) {
    const h = Object.assign({ 'Content-Type': 'application/json' }, extra || {});
    if (TOKEN) h['Authorization'] = 'Bearer ' + TOKEN;
    return h;
  }

  async function api(path, opts) {
    const res = await fetch(API + path, Object.assign({ headers: authHeaders() }, opts || {}));
    if (res.status === 401) {
      const t = window.prompt('请输入控制台令牌（见 config.json 的 panel_token 或启动日志）');
      if (t) {
        TOKEN = t.trim();
        localStorage.setItem('maskit_token', TOKEN);
        return api(path, opts);
      }
      throw new Error('未授权');
    }
    if (!res.ok) {
      let msg = res.status + ' ' + res.statusText;
      try { const j = await res.json(); msg = j.error || msg; } catch (e) {}
      throw new Error(msg);
    }
    return res.json();
  }

  function esc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[c]);
  }

  function fmtTs(ts) {
    if (!ts) return '';
    const d = new Date(ts * 1000);
    return d.toLocaleString('zh-CN', { hour12: false });
  }

  /* ---------- 概览 ---------- */
  async function loadDashboard() {
    const [status, today] = await Promise.all([api('/status'), api('/stats/today')]);
    const c = status.counters || {};
    document.getElementById('statCards').innerHTML = [
      ['请求总数', c.requests], ['已脱敏', c.masked], ['已还原', c.restored],
      ['已阻断', c.blocked], ['透传', c.bypassed], ['错误', c.errors],
    ].map(([k, v]) => `<div class="card"><div class="v">${v == null ? 0 : v}</div><div class="k">${k}</div></div>`).join('');

    const rows = [
      ['监听', status.bind + ':' + status.port],
      ['上游', status.upstream_target || '（未配置）'],
      ['脱敏状态', status.paused ? '已暂停（纯透传）' : '运行中'],
      ['fail-closed', status.fail_closed ? '开启' : '关闭'],
      ['配置版本', status.config_version],
      ['今日请求', today.requests],
      ['今日脱敏事件', today.mask_events],
      ['今日告警', today.alerts],
    ];
    document.getElementById('statusTable').innerHTML =
      rows.map(([k, v]) => `<tr><td>${esc(k)}</td><td class="mono">${esc(v)}</td></tr>`).join('');

    const el = document.getElementById('topStatus');
    el.textContent = status.paused ? '已暂停脱敏' : '运行中 · ' + (status.upstream_target || '未配置上游');
    el.className = 'status ' + (status.upstream_target ? 'ok' : 'bad');
  }

  /* ---------- 规则 ---------- */
  const RULE_LABELS = {
    API_KEY: 'API Key 前缀', CARD: '银行卡（Luhn）', CONNSTR: '连接串密码', EMAIL: '邮箱',
    IDCARD: '身份证（15/18）', LANDLINE: '座机', PHONE: '手机号', ACCESS_KEY: '云厂商 AccessKey',
    HKID: '港澳通行证', IBAN: 'IBAN（mod97）', IP_INTERNAL: '内网 IP（10/172）',
    IP_PRIVATE: '内网 IP（192.168/169.254/100.64）', IP_PUBLIC: '公网 IP', IPV6_PRIVATE: 'IPv6 私网',
    JWT: 'JWT', MAC: 'MAC 地址', PLATE: '车牌', PRIVATE_KEY: 'PEM 私钥',
    SECRET: '密钥键值对', TOKEN: 'Bearer Token', USCC: '统一社会信用代码',
  };

  async function loadRules() {
    const cfg = await api('/config');
    const rules = cfg.mask.builtin_rules || {};
    document.getElementById('ruleToggles').innerHTML = Object.keys(rules).sort().map(k =>
      `<label class="rule-item"><input type="checkbox" data-rule="${esc(k)}" ${rules[k] ? 'checked' : ''}/>${esc(RULE_LABELS[k] || k)} <span class="hint">${esc(k)}</span></label>`
    ).join('');
    document.querySelectorAll('[data-rule]').forEach(cb => {
      cb.onchange = async () => {
        const k = cb.dataset.rule;
        const v = cb.checked;
        await api('/config/patch', {
          method: 'POST',
          body: JSON.stringify({ path: 'mask.builtin_rules.' + k, value: v }),
        });
      };
    });

    const words = cfg.mask.custom_words || {};
    document.getElementById('wordList').innerHTML = Object.keys(words).length
      ? Object.keys(words).map(w =>
        `<tr><td>${esc(w)}</td><td class="hint">${esc(words[w])}</td><td><button data-del-word="${esc(w)}">删除</button></td></tr>`).join('')
      : '<tr><td class="empty">暂无自定义敏感词</td></tr>';
    document.querySelectorAll('[data-del-word]').forEach(b => {
      b.onclick = async () => {
        await api('/config/patch', {
          method: 'POST',
          body: JSON.stringify({ path: 'mask.custom_words', value: removeKey(words, b.dataset.delWord) }),
        });
        loadRules();
      };
    });

    const prefixes = cfg.mask.secret_prefixes || [];
    document.getElementById('prefixList').innerHTML = prefixes.length
      ? prefixes.map(p => `<span class="chip mono">${esc(p)}<button data-del-prefix="${esc(p)}">×</button></span>`).join('')
      : '<span class="hint">无</span>';
    document.querySelectorAll('[data-del-prefix]').forEach(b => {
      b.onclick = async () => {
        await api('/config/patch', {
          method: 'POST',
          body: JSON.stringify({ path: 'mask.secret_prefixes', value: prefixes.filter(x => x !== b.dataset.delPrefix) }),
        });
        loadRules();
      };
    });
  }

  function removeKey(obj, key) {
    const out = {};
    Object.keys(obj).forEach(k => { if (k !== key) out[k] = obj[k]; });
    return out;
  }

  /* ---------- 日志 ---------- */
  async function loadLogs() {
    const f = document.getElementById('logFilter').value;
    const q = '/logs?limit=200' + (f ? '&event_type=' + f : '');
    const data = await api(q);
    const evs = data.events || [];
    document.getElementById('logList').innerHTML = evs.length ? evs.map(renderLogRow).join('')
      : '<tr><td class="empty">暂无事件</td></tr>';
  }

  function renderLogRow(e) {
    const t = String(e.type || '');
    const items = (e.items || []).map(it => {
      const pv = it.cred ? `🔒 ${esc(it.preview)} <span class="hint">sha256:${esc(it.digest)}</span>`
                         : esc(it.preview || it.original || '');
      return `<div>${esc(it.label)}: ${pv}</div>`;
    }).join('');
    const timing = e.mask_ms != null ? `<span class="hint">脱敏 ${Number(e.mask_ms).toFixed(1)}ms</span>` : '';
    return `<tr>
      <td class="mono">${esc(fmtTs(e.ts))}</td>
      <td><span class="badge ${esc(t)}">${esc(t)}</span></td>
      <td class="mono">${esc(e.method)} ${esc(e.path)}</td>
      <td>${esc(e.protocol || '')}${e.unknown_shape ? ' <span class="hint">未知形态</span>' : ''}</td>
      <td class="mono">${esc(e.model || '')}</td>
      <td>${timing} ${e.unresolved ? `<span class="hint">未还原 ${e.unresolved}</span>` : ''}</td>
      <td>${items || `<span class="hint">${esc(e.reason || '')}</span>`}</td>
    </tr>`;
  }

  /* ---------- 审计 ---------- */
  async function loadAudit() {
    const data = await api('/audit/events?limit=200');
    const evs = data.events || [];
    document.getElementById('auditList').innerHTML = evs.length ? evs.map(a => `
      <tr>
        <td class="mono">${esc(fmtTs(a.ts))}</td>
        <td class="sev-${esc(a.severity)}">${esc(a.severity)}</td>
        <td class="mono">${esc(a.signal_type)}</td>
        <td>${esc(a.evidence)}</td>
        <td class="mono hint">${esc(a.method)} ${esc(a.path)}</td>
      </tr>`).join('') : '<tr><td class="empty">暂无审计事件</td></tr>';
  }

  /* ---------- 设置 ---------- */
  async function loadSettings() {
    const cfg = await api('/config');
    document.getElementById('upstreamTarget').value = cfg.upstream.target || '';
    document.getElementById('serverPort').value = cfg.server.port;
    document.getElementById('serverBind').value = cfg.server.bind;
    document.getElementById('maxBodyMib').value = Math.round(cfg.mask.max_body_bytes / 1048576);
    document.getElementById('sessionTtl').value = cfg.mask.session_ttl;
    document.getElementById('failClosed').checked = !!cfg.fail_closed;
    document.getElementById('responseScan').checked = !!cfg.response_scan;
    document.getElementById('streamResponse').checked = !!cfg.stream_response;
    document.getElementById('cmdMode').value = cfg.command_block.mode || 'observe';
    document.getElementById('retentionDays').value = cfg.log_retention_days;
    document.getElementById('panelToken').value = cfg.panel_token || '';
  }

  async function saveSettings() {
    const cfg = await api('/config');
    cfg.upstream.target = document.getElementById('upstreamTarget').value.trim();
    cfg.server.port = parseInt(document.getElementById('serverPort').value, 10) || cfg.server.port;
    cfg.server.bind = document.getElementById('serverBind').value.trim() || cfg.server.bind;
    cfg.mask.max_body_bytes = (parseInt(document.getElementById('maxBodyMib').value, 10) || 32) * 1048576;
    cfg.mask.session_ttl = parseInt(document.getElementById('sessionTtl').value, 10) || 600;
    cfg.fail_closed = document.getElementById('failClosed').checked;
    cfg.response_scan = document.getElementById('responseScan').checked;
    cfg.stream_response = document.getElementById('streamResponse').checked;
    cfg.command_block.mode = document.getElementById('cmdMode').value;
    cfg.log_retention_days = parseInt(document.getElementById('retentionDays').value, 10) || 7;
    cfg.panel_token = document.getElementById('panelToken').value.trim();
    const r = await api('/config', { method: 'POST', body: JSON.stringify(cfg) });
    const msg = document.getElementById('saveMsg');
    msg.textContent = '已保存' + ((r.warnings || []).length ? '（告警：' + r.warnings.join('；') + '）' : '') +
      '；端口/绑定变更需重启进程生效';
    setTimeout(() => { msg.textContent = ''; }, 8000);
  }

  /* ---------- 事件绑定 ---------- */
  function bind() {
    document.querySelectorAll('.tab').forEach(t => {
      t.onclick = () => {
        document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
        document.querySelectorAll('.page').forEach(x => x.classList.remove('active'));
        t.classList.add('active');
        const id = 'page-' + t.dataset.page;
        document.getElementById(id).classList.add('active');
        const reload = {
          dashboard: loadDashboard, rules: loadRules, logs: loadLogs,
          audit: loadAudit, settings: loadSettings,
        }[t.dataset.page];
        if (reload) reload().catch(err => alert('加载失败：' + err.message));
      };
    });

    document.getElementById('btnPause').onclick = () => api('/proxy/pause', { method: 'POST' }).then(loadDashboard);
    document.getElementById('btnResume').onclick = () => api('/proxy/resume', { method: 'POST' }).then(loadDashboard);
    document.getElementById('btnRefreshLogs').onclick = () => loadLogs();
    document.getElementById('logFilter').onchange = () => loadLogs();
    document.getElementById('btnClearLogs').onclick = () => {
      if (confirm('清空事件日志？（统计摘要保留）')) api('/logs/clear', { method: 'POST' }).then(loadLogs);
    };
    document.getElementById('btnRefreshAudit').onclick = () => loadAudit();
    document.getElementById('btnClearAudit').onclick = () => {
      if (confirm('清空审计事件？')) api('/audit/clear', { method: 'POST' }).then(loadAudit);
    };
    document.getElementById('btnAddWord').onclick = async () => {
      const w = document.getElementById('newWord').value.trim();
      const l = document.getElementById('newLabel').value.trim() || 'TERM';
      if (!w) return;
      await api('/config/patch', { method: 'POST', body: JSON.stringify({ path: 'mask.custom_words.' + w, value: l }) });
      document.getElementById('newWord').value = '';
      loadRules();
    };
    document.getElementById('btnAddPrefix').onclick = async () => {
      const p = document.getElementById('newPrefix').value.trim();
      if (!p) return;
      const cfg = await api('/config');
      const list = (cfg.mask.secret_prefixes || []).concat([p]);
      await api('/config/patch', { method: 'POST', body: JSON.stringify({ path: 'mask.secret_prefixes', value: list }) });
      document.getElementById('newPrefix').value = '';
      loadRules();
    };
    document.getElementById('btnSave').onclick = () => saveSettings().catch(e => alert('保存失败：' + e.message));
    document.getElementById('btnRotateToken').onclick = () => {
      const a = new Uint8Array(18);
      crypto.getRandomValues(a);
      document.getElementById('panelToken').value =
        Array.from(a).map(b => 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789'[b % 56]).join('');
    };
  }

  bind();
  loadDashboard().catch(err => {
    const el = document.getElementById('topStatus');
    el.textContent = '连接失败：' + err.message;
    el.className = 'status bad';
  });
  setInterval(() => loadDashboard().catch(() => {}), 5000);
})();
