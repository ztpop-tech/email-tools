
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
        var qname = '_mta-sts.' + domain + '. ';
        result.innerHTML = '<div style="color:#666;font-size:14px;padding:8px 0">正在查询 <code style="background:#f0f0f0;padding:2px 6px;border-radius:4px">' + esc(qname) + '</code> ...</div>';
        dohQuery(qname, function(err, j) {
            if (err) {
                result.innerHTML = statusBox('err', 'DNS 查询失败：' + esc(err.message) + '。请检查网络连接后重试。');
                return;
            }
            var txts = parseTxtRecords(j.Answer);
            
            var html = '';
            if (txts.length === 0) {
                html += statusBox('err', '未在 <code>_mta-sts.' + esc(domain) + '</code> 发现 MTA-STS 策略发现记录。') +
                    statusBox('warn', '域名未启用 MTA-STS，SMTP 传输存在降级攻击（STRIPTLS）风险。可用本站 <a href="/tools/mta-sts-generator.html" style="color:#0066cc">MTA-STS 生成器</a> 生成发现记录与策略文件。');
            } else {
                var mta = txts[0];
                html += statusBox('ok', '<b>✓ 发现 MTA-STS 发现记录</b>');
                html += '<pre style="background:#1a1a2e;color:#e0e0e0;padding:14px;border-radius:6px;font-size:13.5px;overflow-x:auto;white-space:pre-wrap;word-break:break-all">' + esc(mta) + '</pre>';
                if (mta.indexOf('v=STSv1') !== 0) html += statusBox('err', '⚠ 记录不以 <code>v=STSv1</code> 开头，格式错误（RFC 8461 §3.1）。');
            }
            // 尝试抓取策略文件
            html += '<div style="margin:14px 0 8px;font-size:14px;color:#555"><b>策略文件检查</b>（https://mta-sts.' + esc(domain) + '/.well-known/mta-sts.txt）</div>';
            fetch('https://mta-sts.' + domain + '/.well-known/mta-sts.txt', { method: 'GET' })
                .then(function(r) {
                    if (!r.ok) throw new Error('HTTP ' + r.status);
                    return r.text();
                })
                .then(function(text) {
                    var lines = text.trim().split(/\\r?\\n/);
                    var ok = lines.some(function(l) { return l.indexOf('version: STSv1') === 0; });
                    html += statusBox(ok ? 'ok' : 'err', (ok ? '<b>✓ 策略文件存在</b>' : '⚠ 策略文件格式异常（缺 version: STSv1）') + '，内容如下：');
                    html += '<pre style="background:#1a1a2e;color:#e0e0e0;padding:14px;border-radius:6px;font-size:13px;overflow-x:auto;white-space:pre-wrap;word-break:break-all">' + esc(text.slice(0, 1500)) + '</pre>';
                    var enforce = lines.some(function(l) { return l.indexOf('mode: enforce') === 0; });
                    if (ok && enforce) html += statusBox('ok', '模式为 <code>enforce</code>：强制 TLS，未加密连接将被拒绝。');
                    else if (ok) html += statusBox('warn', '模式非 enforce（testing 或缺失）：仅测试阶段，不会强制 TLS。');
                    result.innerHTML = html;
                })
                .catch(function(e) {
                    html += statusBox('warn', '无法获取策略文件（' + esc(e.message) + '）。若浏览器跨域限制或服务器未部署 HTTPS，可稍后手动访问验证。');
                    result.innerHTML = html;
                });

        });
    });
})();
