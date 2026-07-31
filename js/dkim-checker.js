
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
        var qname = selector + '._domainkey.' + domain + '. ';
        result.innerHTML = '<div style="color:#666;font-size:14px;padding:8px 0">正在查询 <code style="background:#f0f0f0;padding:2px 6px;border-radius:4px">' + esc(qname) + '</code> ...</div>';
        dohQuery(qname, function(err, j) {
            if (err) {
                result.innerHTML = statusBox('err', 'DNS 查询失败：' + esc(err.message) + '。请检查网络连接后重试。');
                return;
            }
            var txts = parseTxtRecords(j.Answer);
            
            if (txts.length === 0) {
                result.innerHTML = statusBox('err', '未在 <code>' + esc(qname) + '</code> 发现 DKIM 记录。') +
                    statusBox('warn', '请检查：① 选择器是否正确（发件服务商提供，如 default/google/s1）；② DNS 记录是否已生效（等待 TTL）。可用本站 <a href="/tools/dkim-generator.html" style="color:#0066cc">DKIM 生成器</a> 生成密钥对与记录。');
                return;
            }
            var dkim = txts[0];
            var html = statusBox('ok', '<b>✓ 发现 DKIM 记录</b>（' + txts.length + ' 条 TXT，取第一条）');
            html += '<pre style="background:#1a1a2e;color:#e0e0e0;padding:14px;border-radius:6px;font-size:13.5px;overflow-x:auto;white-space:pre-wrap;word-break:break-all">' + esc(dkim) + '</pre>';
            var tags = {};
            dkim.split(';').forEach(function(s) {
                var i = s.indexOf('=');
                if (i > 0) tags[s.slice(0, i).trim().toLowerCase()] = s.slice(i + 1).trim();
            });
            var rows = [];
            var pubkey = tags['p'] || '';
            if (pubkey) {
                rows.push(['p', pubkey.length > 40 ? pubkey.slice(0, 40) + '…' : pubkey, '公钥（Base64）。长度约 ' + pubkey.length + ' 字符']);
                var bits = pubkey.length >= 392 ? '≥2048 位（强）' : pubkey.length >= 196 ? '1024 位（RFC 8301 后不建议）' : '偏弱';
                rows.push(['密钥强度', bits, '按公钥 Base64 长度估算']);
            }
            if (tags['v']) rows.push(['v', tags['v'], '版本（应为 DKIM1）']);
            if (tags['k']) rows.push(['k', tags['k'], '密钥类型（rsa 为主）']);
            if (tags['s']) rows.push(['s', tags['s'], '服务类型（* 或 email）']);
            if (tags['t']) rows.push(['t', tags['t'], '标志（y=测试模式，s=严格）']);
            if (tags['h']) rows.push(['h', tags['h'], '签名哈希算法（sha1/sha256）']);
            html += keyValTable(rows);
            if (!tags['p']) html += statusBox('err', '⚠ 记录缺少 <code>p=</code> 公钥标签，DKIM 验签将失败。');
            else if (tags['k'] === 'ed25519') html += statusBox('ok', 'ED25519 密钥（RFC 8463），现代算法。');
            else if (pubkey.length < 196) html += statusBox('warn', '⚠ 公钥疑似低于 1024 位，建议升级到 2048 位（RFC 8301）。');
            result.innerHTML = html;

        });
    });
})();
