
let mechCount = 0;
const MECH_TYPES = [
    {v:'ip4', label:'ip4 — 单个 IPv4 或网段', ph:'如 203.0.113.10 或 203.0.113.0/24'},
    {v:'ip6', label:'ip6 — 单个 IPv6 或网段', ph:'如 2001:db8::10 或 2001:db8::/32'},
    {v:'include', label:'include — 引入其他域的 SPF', ph:'如 _spf.google.com'},
    {v:'mx', label:'mx — 使用 MX 记录对应的 IP', ph:'（可留空）'},
    {v:'a', label:'a — 使用 A 记录对应的 IP', ph:'如 mail.example.com 或留空用本域'}
];
function addMech() {
    const list = document.getElementById('mechList');
    const row = document.createElement('div');
    row.className = 'mech-row';
    row.innerHTML = `
        <select>${MECH_TYPES.map((m,i)=>`<option value="${m.v}" ${i===0?'selected':''}>${m.label}</option>`).join('')}</select>
        <input type="text" placeholder="${MECH_TYPES[0].ph}">
        <button onclick="this.parentNode.remove()">✕</button>`;
    list.appendChild(row);
    mechCount++;
    // 默认添加 2 行
    if (mechCount <= 2 && list.children.length < 2) { /* no-op */ }
}
// 预置两个常用行
addMech();
addMech();

function mechNeedsValue(type) {
    return type === 'ip4' || type === 'ip6' || type === 'include' || type === 'a';
}

function generate() {
    const rows = document.querySelectorAll('#mechList .mech-row');
    const parts = ['v=spf1'];
    let dnsQueries = 0; // v=spf1 本身不算
    const warnings = [];
    let hasAll = false;

    rows.forEach(row => {
        const type = row.querySelector('select').value;
        const value = row.querySelector('input').value.trim();
        const qualifier = document.querySelector('input[name=qualifier]:checked').value;

        if (type === 'mx') {
            parts.push(qualifier + 'mx');
            dnsQueries++;
            return;
        }
        if (type === 'a') {
            if (value) {
                parts.push(qualifier + 'a:' + value);
                dnsQueries++;
            } else {
                parts.push(qualifier + 'a');
                dnsQueries++;
            }
            return;
        }
        if (!value) {
            warnings.push('有机制未填写值，已忽略: ' + type);
            return;
        }
        if (type === 'ip4') {
            if (!/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(value)) {
                warnings.push('ip4 格式可能不正确（应为 x.x.x.x 或 x.x.x.x/xx）: ' + value);
            }
            parts.push(qualifier + 'ip4:' + value);
        } else if (type === 'ip6') {
            if (!value.includes(':')) {
                warnings.push('ip6 格式可能不正确: ' + value);
            }
            parts.push(qualifier + 'ip6:' + value);
        } else if (type === 'include') {
            parts.push(qualifier + 'include:' + value);
            dnsQueries += 2; // include 自身 + 其展开
        }
    });

    const allMod = document.querySelector('input[name=allMod]:checked').value;
    parts.push(allMod);
    hasAll = true;

    // 校验 10 次 DNS 上限（RFC 7208 §4.6.4）
    const record = parts.join(' ');

    const v = document.getElementById('validation');
    if (dnsQueries > 10) {
        v.className = 'validation warn';
        v.style.display = 'block';
        v.innerHTML = `⚠️ <strong>DNS 查询次数估算 ${dnsQueries} 次，超过 RFC 7208 规定的 10 次上限</strong>，收件方会返回 permerror 导致 SPF 失效。请减少 include/mx/a 机制数量。`;
    } else if (dnsQueries >= 8) {
        v.className = 'validation warn';
        v.style.display = 'block';
        v.innerHTML = `⚠️ DNS 查询次数估算 ${dnsQueries} 次，接近 10 次上限（RFC 7208 §4.6.4）。建议精简机制。`;
    } else {
        v.className = 'validation ok';
        v.style.display = 'block';
        v.innerHTML = `✅ DNS 查询估算 ${dnsQueries} 次（上限 10 次，RFC 7208 §4.6.4）${warnings.length ? '<br>⚠️ ' + warnings.join('<br>⚠️ ') : ''}`;
    }

    // 输出
    const out = document.getElementById('output');
    out.style.display = 'block';
    out.innerHTML = `<button class="copy-btn" onclick="copyRec(this)">复制</button><strong>SPF TXT 记录</strong>（主机名：@ 或留空）<br><br>${record}`;

    const out2 = document.getElementById('output2');
    out2.style.display = 'block';
    out2.innerHTML = `<button class="copy-btn" onclick="copyRec(this)">复制</button><strong>BIND 区域文件格式</strong><br><br>@ IN TXT "${record}"`;
}

function copyRec(btn) {
    const text = btn.parentNode.innerText.replace('复制', '').trim();
    navigator.clipboard.writeText(text).then(() => {
        btn.textContent = '已复制 ✓';
        setTimeout(() => btn.textContent = '复制', 1500);
    });
}
