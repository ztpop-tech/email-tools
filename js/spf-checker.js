
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
        var qname = domain + '. ';
        result.innerHTML = '<div style="color:#666;font-size:14px;padding:8px 0">正在查询 <code style="background:#f0f0f0;padding:2px 6px;border-radius:4px">' + esc(qname) + '</code> ...</div>';
        dohQuery(qname, function(err, j) {
            if (err) {
                result.innerHTML = statusBox('err', 'DNS 查询失败：' + esc(err.message) + '。请检查网络连接后重试。');
                return;
            }
            var txts = parseTxtRecords(j.Answer);
            
            if (txts.length === 0) {
                result.innerHTML = statusBox('warn', '未发现 SPF 记录（TXT 记录中无 v=spf1 开头项）。') +
                    statusBox('err', '该域名未部署 SPF，发往此域名的邮件将无法通过 SPF 校验，伪造风险高。建议立即配置 SPF 记录（可用本站 <a href="/tools/spf-generator.html" style="color:#0066cc">SPF 生成器</a>）。');
                return;
            }
            var spf = null;
            for (var i = 0; i < txts.length; i++) {
                if (txts[i].indexOf('v=spf1') === 0) { spf = txts[i]; break; }
            }
            if (!spf) {
                result.innerHTML = statusBox('warn', '未发现 SPF 记录。以下为域名全部 TXT 记录：') + txts.map(function(t){return '<pre style="background:#1a1a2e;color:#e0e0e0;padding:12px;border-radius:6px;font-size:13px;overflow-x:auto">' + esc(t) + '</pre>';}).join('');
                return;
            }
            var html = statusBox('ok', '<b>✓ 发现 SPF 记录</b>（<code>v=spf1</code> 开头）');
            html += '<pre style="background:#1a1a2e;color:#e0e0e0;padding:14px;border-radius:6px;font-size:13.5px;overflow-x:auto;white-space:pre-wrap;word-break:break-all">' + esc(spf) + '</pre>';
            // 逐机制解析
            var parts = spf.split(/\s+/);
            var rows = [];
            var dnsQueries = 1; // 初始 TXT 查询
            var hasAll = false;
            for (var i = 1; i < parts.length; i++) {
                var p = parts[i];
                if (!p) continue;
                var m = p.match(/^([+\-~?]?)([a-z0-9]+)(?::(.*))?$/i);
                if (!m) { rows.push([p, '—', '无法识别的机制']); continue; }
                var qual = m[1] || '+';
                var mech = m[2].toLowerCase();
                var arg = m[3] || '';
                var qmap = { '+': '通过 (Pass)', '-': '失败 (Fail)', '~': '软失败 (SoftFail)', '?': '中立 (Neutral)' };
                var desc = '';
                if (mech === 'all') { desc = '匹配所有来源（必须为最后一项）。' + qmap[qual]; hasAll = true; }
                else if (mech === 'include') { desc = '引入其他域名的 SPF 记录（消耗 1 次 DNS 查询）。'; dnsQueries++; }
                else if (mech === 'ip4') { desc = '允许的 IPv4 地址/段。'; }
                else if (mech === 'ip6') { desc = '允许的 IPv6 地址/段。'; }
                else if (mech === 'mx') { desc = 'MX 记录指向的服务器（若需解析消耗 1 次查询）。'; dnsQueries++; }
                else if (mech === 'a') { desc = '域名的 A/AAAA 记录（若需解析消耗 1 次查询）。'; dnsQueries++; }
                else if (mech === 'ptr') { desc = 'PTR 反向解析（RFC 7208 不推荐，性能差）。'; }
                else if (mech === 'exists') { desc = '按 A 记录存在性匹配（消耗 1 次查询）。'; dnsQueries++; }
                else if (mech === 'redirect') { desc = '重定向到其他域名的 SPF（消耗 1 次查询）。'; dnsQueries++; }
                else { desc = '未知机制'; }
                rows.push([(qual === '+' ? '+' : qual) + mech + (arg ? ':' + arg : ''), arg || '—', desc]);
            }
            html += keyValTable(rows);
            if (!hasAll) html += statusBox('warn', '⚠ 记录缺少 <code>all</code> 终结符（RFC 7208 §4.7 要求）。未匹配的发送方将得到 Neutral 结果，反伪造效果为零。');
            if (dnsQueries > 10) html += statusBox('err', '⚠ 估算 DNS 查询次数约 ' + dnsQueries + ' 次，超过 RFC 7208 §4.6.4 的 10 次上限，将导致 permerror。建议精简 include/mx 机制。');
            else html += statusBox('ok', '估算 DNS 查询次数：' + dnsQueries + ' 次（RFC 7208 §4.6.4 上限 10 次）' + (dnsQueries > 7 ? '，接近上限，建议精简' : '，合规'));
            result.innerHTML = html;

        });
    });
})();
