
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
        var qname = '_smtp._tls.' + domain + '. ';
        result.innerHTML = '<div style="color:#666;font-size:14px;padding:8px 0">正在查询 <code style="background:#f0f0f0;padding:2px 6px;border-radius:4px">' + esc(qname) + '</code> ...</div>';
        dohQuery(qname, function(err, j) {
            if (err) {
                result.innerHTML = statusBox('err', 'DNS 查询失败：' + esc(err.message) + '。请检查网络连接后重试。');
                return;
            }
            var txts = parseTxtRecords(j.Answer);
            
            if (txts.length === 0) {
                result.innerHTML = statusBox('warn', '未在 <code>_smtp._tls.' + esc(domain) + '</code> 发现 TLS-RPT 记录。') +
                    statusBox('info', '域名未配置 TLS 传输失败报告。建议与 MTA-STS / DANE 同步部署：用本站 <a href="/tools/tls-rpt-generator.html" style="color:#0066cc">TLS-RPT 生成器</a> 生成记录，接收聚合报告以监控 TLS 传输健康度。');
                return;
            }
            var rpt = txts[0];
            var html = statusBox('ok', '<b>✓ 发现 TLS-RPT 记录</b>');
            html += '<pre style="background:#1a1a2e;color:#e0e0e0;padding:14px;border-radius:6px;font-size:13.5px;overflow-x:auto;white-space:pre-wrap;word-break:break-all">' + esc(rpt) + '</pre>';
            if (rpt.indexOf('v=TLSRPTv1') !== 0) {
                html += statusBox('err', '⚠ 记录不以 <code>v=TLSRPTv1</code> 开头，格式错误（RFC 8460 §3）。');
            } else {
                var rua = rpt.match(/rua=([^;]+)/);
                if (rua) {
                    var uris = rua[1].split(',').map(function(u) { return u.trim(); });
                    html += keyValTable(uris.map(function(u, i) { return ['rua[' + i + ']', u, u.indexOf('mailto:') === 0 ? '聚合报告接收地址' : '非 mailto URI（目前仅支持 mailto）']; }));
                } else {
                    html += statusBox('err', '⚠ 记录缺少 <code>rua=</code> 报告地址，报告将无处可发。');
                }
            }
            html += statusBox('info', 'TLS-RPT 本身不改变邮件传输行为，仅收集 MTA-STS/DANE 策略下的 TLS 失败报告，是邮件安全策略的监控仪表盘。');
            result.innerHTML = html;

        });
    });
})();
