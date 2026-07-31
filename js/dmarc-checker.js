
(function() {
    'use strict';
    var btn = document.getElementById('check-btn');
    var result = document.getElementById('result');

    function esc(s) {
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function statusBox(cls, msg) {
        return '<div style="padding:14px 18px;border-radius:8px;margin-bottom:12px;font-size:14.5px;line-height:1.7;' +
            (cls === 'err' ? 'background:#fdecea;border:1px solid #f5c6cb;color:#a94442' :
             cls === 'warn' ? 'background:#fff8e1;border:1px solid #ffe082;color:#8a6d3b' :
             'background:#e8f5e9;border:1px solid #c8e6c9;color:#2e7d32') + '">' + msg + '</div>';
    }

    function keyValTable(rows) {
        var h = '<table style="border-collapse:collapse;width:100%;font-size:14px;margin:12px 0">' +
            '<tr style="background:#f0f4f8"><th style="padding:8px 12px;border:1px solid #ddd;text-align:left">标签</th>' +
            '<th style="padding:8px 12px;border:1px solid #ddd;text-align:left">值</th>' +
            '<th style="padding:8px 12px;border:1px solid #ddd;text-align:left">说明</th></tr>';
        rows.forEach(function(r) {
            h += '<tr><td style="padding:8px 12px;border:1px solid #ddd;font-family:monospace">' + esc(r[0]) + '</td>' +
                '<td style="padding:8px 12px;border:1px solid #ddd;font-family:monospace;word-break:break-all">' + esc(r[1]) + '</td>' +
                '<td style="padding:8px 12px;border:1px solid #ddd">' + r[2] + '</td></tr>';
        });
        return h + '</table>';
    }

    function parseTxtRecords(answers) {
        var txts = [];
        (answers || []).forEach(function(a) {
            if (a.type === 16) txts.push(a.data);
        });
        return txts;
    }

    function dohQuery(qname, cb) {
        var url = 'https://dns.alidns.com/resolve?name=' + encodeURIComponent(qname) + '&type=TXT';
        fetch(url, { headers: { 'accept': 'application/dns-json' } })
            .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
            .then(function(j) { cb(null, j); })
            .catch(function(e) { cb(e); });
    }

    btn.addEventListener('click', function() {
        var domain = document.getElementById('domain-input').value.trim().toLowerCase();
        var selector = document.getElementById('selector-input') ? document.getElementById('selector-input').value.trim() : '';
        if (!domain || !/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(domain)) {
            result.innerHTML = statusBox('err', '请输入有效域名，如 example.com');
            return;
        }
        var qname = '_dmarc.' + domain + '. ';
        result.innerHTML = '<div style="color:#666;font-size:14px;padding:8px 0">正在查询 <code style="background:#f0f0f0;padding:2px 6px;border-radius:4px">' + esc(qname) + '</code> ...</div>';
        dohQuery(qname, function(err, j) {
            if (err) {
                result.innerHTML = statusBox('err', 'DNS 查询失败：' + esc(err.message) + '。请检查网络连接后重试。');
                return;
            }
            var txts = parseTxtRecords(j.Answer);
            
            if (txts.length === 0) {
                result.innerHTML = statusBox('err', '未在 <code>_dmarc.' + esc(domain) + '</code> 发现 DMARC 记录。') +
                    statusBox('warn', '该域名未部署 DMARC，任何声称该域名的邮件都无法通过 DMARC 校验。建议用本站 <a href="/tools/dmarc-generator.html" style="color:#0066cc">DMARC 生成器</a> 生成记录，按 p=none → quarantine → reject 渐进部署（参考 <a href="/kb/dmarc-policy-gradual.html" style="color:#0066cc">DMARC 策略渐进指南</a>）。');
                return;
            }
            var dmarc = null;
            for (var i = 0; i < txts.length; i++) {
                if (txts[i].indexOf('v=DMARC1') === 0) { dmarc = txts[i]; break; }
            }
            if (!dmarc) {
                result.innerHTML = statusBox('warn', '该位置有 TXT 记录但不是 DMARC 记录（不以 v=DMARC1 开头）：') + txts.map(function(t){return '<pre style="background:#1a1a2e;color:#e0e0e0;padding:12px;border-radius:6px;font-size:13px">' + esc(t) + '</pre>';}).join('');
                return;
            }
            var html = statusBox('ok', '<b>✓ 发现 DMARC 记录</b>');
            html += '<pre style="background:#1a1a2e;color:#e0e0e0;padding:14px;border-radius:6px;font-size:13.5px;overflow-x:auto;white-space:pre-wrap;word-break:break-all">' + esc(dmarc) + '</pre>';
            var tags = {};
            dmarc.split(';').forEach(function(s) {
                var i = s.indexOf('=');
                if (i > 0) tags[s.slice(0, i).trim().toLowerCase()] = s.slice(i + 1).trim();
            });
            var rows = [];
            var policy = (tags['p'] || '').toLowerCase();
            var policyDesc = { 'none': '仅监控（不拦截，收集报告）', 'quarantine': '隔离（进垃圾箱）', 'reject': '拒绝（退信）' };
            if (tags['v']) rows.push(['v', tags['v'], '版本（应为 DMARC1）']);
            if (tags['p']) rows.push(['p', tags['p'], '主域策略：' + (policyDesc[policy] || '未知')]);
            if (tags['sp']) rows.push(['sp', tags['sp'], '子域策略（缺省继承 p）']);
            if (tags['pct']) rows.push(['pct', tags['pct'], '策略应用百分比（' + tags['pct'] + '% 的邮件应用策略）']);
            if (tags['rua']) rows.push(['rua', tags['rua'], '聚合报告接收地址']);
            if (tags['ruf']) rows.push(['ruf', tags['ruf'], '取证报告（失败详情）接收地址']);
            if (tags['fo']) rows.push(['fo', tags['fo'], '取证报告触发条件（0=全部失败，1=任一失败，d/s=DKIM/SPF）']);
            if (tags['adkim']) rows.push(['adkim', tags['adkim'], 'DKIM 对齐模式（r=宽松，s=严格）']);
            if (tags['aspf']) rows.push(['aspf', tags['aspf'], 'SPF 对齐模式（r=宽松，s=严格）']);
            html += keyValTable(rows);
            var level = policy === 'reject' ? 3 : policy === 'quarantine' ? 2 : policy === 'none' ? 1 : 0;
            if (level === 0) html += statusBox('err', '⚠ 缺少 <code>p=</code> 策略标签，记录无效（RFC 7489 要求）。');
            else if (level === 1) html += statusBox('warn', '策略为 <code>none</code>：仅监控阶段。建议观察 rua 报告 1-2 周后逐步收紧到 quarantine → reject。');
            else if (level === 2) html += statusBox('warn', '策略为 <code>quarantine</code>：未通过认证的邮件将进垃圾箱。稳定后可考虑升级到 reject。');
            else html += statusBox('ok', '策略为 <code>reject</code>：最强保护，未通过认证的邮件将被拒绝。');
            if (!tags['rua']) html += statusBox('warn', '⚠ 缺少 <code>rua=</code>，无法接收聚合报告，建议补充。');
            result.innerHTML = html;

        });
    });
})();
