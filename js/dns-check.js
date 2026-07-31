
// DNS-over-HTTPS via Google
const DOH_URL = 'https://dns.google/resolve';
const CACHE_TIME = 0; // Always fresh queries

async function dnsQuery(name, type) {
    const url = `${DOH_URL}?name=${encodeURIComponent(name)}&type=${type}&cd=1`;
    try {
        const resp = await fetch(url);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        if (data.Status !== 0) {
            // NXDOMAIN or other error
            return { status: data.Status, answers: [], authority: data.Authority || [] };
        }
        return { status: 0, answers: data.Answer || [], authority: data.Authority || [] };
    } catch (e) {
        return { status: -1, answers: [], error: e.message };
    }
}

function checkResult(result, checkType) {
    if (result.status === -1) return { level: 'fail', msg: 'DNS 查询失败: ' + result.error };
    if (result.status === 3) return { level: 'fail', msg: '域名不存在 (NXDOMAIN)' };
    if (result.answers.length === 0) {
        if (result.status === 0) return { level: 'warn', msg: '未配置（查询成功但无记录）' };
        return { level: 'warn', msg: 'DNS 查询返回异常状态: ' + result.status };
    }
    return { level: 'pass', msg: '', answers: result.answers };
}

function getDataStr(answer) {
    return answer.data || '';
}

async function checkSPF(domain) {
    const r = await dnsQuery(domain, 'TXT');
    const cr = checkResult(r, 'SPF');
    if (cr.level !== 'pass') return { ...cr, label: 'SPF 发件人策略框架', rfc: 'RFC 7208' };
    const spfRecords = cr.answers.filter(a => getDataStr(a).toLowerCase().includes('v=spf1'));
    if (spfRecords.length === 0) return { level: 'fail', label: 'SPF 发件人策略框架', rfc: 'RFC 7208',
        msg: '未找到 SPF 记录（TXT 记录中无 v=spf1 标记）。SPF 是邮件认证的基础，缺少将导致邮件容易被拒收或进垃圾箱。',
        detail: '<p>请在 DNS 中添加 TXT 记录：<code>v=spf1 mx ~all</code>（最简配置）或 <code>v=spf1 ip4:你的IP ~all</code></p>' };
    if (spfRecords.length > 1) return { level: 'warn', label: 'SPF 发件人策略框架', rfc: 'RFC 7208',
        msg: `检测到 ${spfRecords.length} 条 SPF 记录（RFC 7208 §3.2 规定每个域最多一条 SPF 记录，多条会导致 permerror）`,
        detail: spfRecords.map(a => `<code class="spf-code">${getDataStr(a).replace(/</g,'&lt;').replace(/>/g,'&gt;')}</code>`).join('<br>') };
    const spf = getDataStr(spfRecords[0]);
    const escaped = spf.replace(/</g,'&lt;').replace(/>/g,'&gt;');
    let notes = [];
    let level = 'pass';
    if (spf.includes('+all')) { level = 'fail'; notes.push('⚠️ <code>+all</code> 表示允许任意主机发送，相当于没有 SPF 保护'); }
    else if (spf.includes('?all')) notes.push('⚠️ <code>?all</code> 为中性策略（neutral），建议使用 <code>~all</code> (softfail) 或 <code>-all</code> (hardfail)');
    else if (spf.includes('~all')) notes.push('💡 <code>~all</code> (softfail) 是推荐的渐进策略，切换到 <code>-all</code> 前请先验证所有合法发信源已纳入');
    else if (spf.includes('-all')) notes.push('✅ <code>-all</code> (hardfail) 严格策略，确保所有合法发信源已正确配置');
    const hasMX = spf.includes(' mx') || spf.includes(':mx');
    const hasA = spf.includes(' a') || spf.includes(':a');
    if (spf.split(' ').length > 10) notes.push('⚠️ SPF 记录包含超过 10 个机制/修饰符，注意 DNS 查询限制（RFC 7208 §4.6.4: 最多 10 次查询），超过会触发 permerror');
    return { level, label: 'SPF 发件人策略框架', rfc: 'RFC 7208',
        msg: `SPF 记录已配置${notes.length ? '，' + notes.join('；') : '，配置合理'}`,
        detail: `<code class="spf-code">${escaped}</code>` };
}

async function checkDKIM(domain, selectors) {
    const results = [];
    for (const sel of selectors) {
        const name = `${sel}._domainkey.${domain}`;
        const r = await dnsQuery(name, 'TXT');
        const cr = checkResult(r, 'DKIM');
        if (cr.level === 'pass') {
            const data = getDataStr(cr.answers[0]);
            if (data.includes('v=DKIM1') || data.includes('k=rsa') || data.includes('p=')) {
                const p = data.match(/p=([^;]+)/);
                const keyLen = p ? p[1].length : 0;
                const note = keyLen < 270 ? '（密钥过短，建议 ≥2048-bit RSA）' : (keyLen >= 392 ? '（推荐长度）' : '');
                results.push({ level: 'pass', selector: sel, data: data, keyLen: keyLen, note });
            } else {
                results.push({ level: 'warn', selector: sel, msg: '记录存在但格式异常，可能不是 DKIM 公钥记录' });
            }
        } else if (cr.level === 'warn') {
            results.push({ level: 'warn', selector: sel, msg: '未配置此 selector' });
        } else {
            results.push({ level: 'warn', selector: sel, msg: '查询失败' });
        }
    }
    // Also try common selectors if not found
    const found = results.filter(r => r.level === 'pass');
    if (results.length === 0) {
        return { level: 'warn', label: 'DKIM 域名密钥识别邮件', rfc: 'RFC 6376',
            msg: '未配置 DKIM selector。请联系 MTA 管理员获取 DKIM selector 名称（通常为 default），然后查询对应 TXT 记录。',
            detail: '<p>DKIM 公钥格式：<br><code>v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG...</code><br>存储在 <code>&lt;selector&gt;._domainkey.&lt;domain&gt;</code> 的 TXT 记录中（RFC 6376 §3.6.2.2）</p>' };
    }
    return { level: 'pass', label: 'DKIM 域名密钥识别邮件', rfc: 'RFC 6376',
        msg: `检测到 ${found.length} 个 DKIM selector`,
        selectors: results };
}

async function checkDMARC(domain) {
    const r = await dnsQuery(`_dmarc.${domain}`, 'TXT');
    const cr = checkResult(r, 'DMARC');
    if (cr.level !== 'pass') return { level: 'fail', label: 'DMARC 基于域的消息认证', rfc: 'RFC 7489',
        msg: '未配置 DMARC 记录。缺少 DMARC 将无法向 Gmail/Yahoo 等主流邮箱证明邮件的认证状态，2024 年起 Gmail 和 Yahoo 强制要求发送者配置 DMARC（最低 p=none）。',
        detail: '<p>请在 DNS 中添加 TXT 记录（名称 <code>_dmarc</code>）：<br><code>v=DMARC1; p=none; rua=mailto:dmarc@' + domain + '</code></p>' };
    const data = getDataStr(cr.answers[0]);
    if (!data.includes('v=DMARC1')) return { level: 'fail', label: 'DMARC 基于域的消息认证', rfc: 'RFC 7489',
        msg: 'DMARC 记录格式错误：缺少 v=DMARC1 标记',
        detail: `<code>${data.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</code>` };
    const pMatch = data.match(/p=(\w+)/);
    const pctMatch = data.match(/pct=(\d+)/);
    const ruaMatch = data.match(/rua=([^;]+)/);
    const policy = pMatch ? pMatch[1] : 'unknown';
    let level = 'pass';
    let notes = [];
    if (policy === 'none') notes.push('💡 当前策略为 <code>p=none</code>（仅监控），建议在验证数据无误后升级到 <code>p=quarantine</code> 或 <code>p=reject</code>');
    else if (policy === 'quarantine') notes.push('✅ <code>p=quarantine</code> 隔离策略');
    else if (policy === 'reject') notes.push('✅ <code>p=reject</code> 严格拒绝策略');
    if (!ruaMatch) notes.push('⚠️ 未配置 <code>rua</code> 聚合报告地址，将无法接收 DMARC 每日报告');
    const pct = pctMatch ? parseInt(pctMatch[1]) : 100;
    if (pct < 100) notes.push(`⚠️ <code>pct=${pct}</code>：仅对 ${pct}% 的邮件应用策略`);
    return { level, label: 'DMARC 基于域的消息认证', rfc: 'RFC 7489',
        msg: `DMARC 已配置（策略: ${policy}）${notes.length ? '，' + notes.join('；') : ''}`,
        detail: `<code>${data.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</code>` };
}

async function checkMX(domain) {
    const r = await dnsQuery(domain, 'MX');
    const cr = checkResult(r, 'MX');
    if (cr.level !== 'pass') return { level: 'fail', label: 'MX 邮件交换记录', rfc: 'RFC 5321 §5',
        msg: '未配置 MX 记录。没有 MX 记录意味着该域无法接收外部邮件。',
        detail: '<p>请在 DNS 中添加 MX 记录，指向邮件服务器的 A 记录或主机名。</p>' };
    const mxs = cr.answers.filter(a => a.type === 15); // MX type
    const sorted = [...mxs].sort((a,b) => (a.preference||99) - (b.preference||99));
    const detail = sorted.map(a => `MX ${a.preference} → ${a.data.replace(/</g,'&lt;').replace(/>/g,'&gt;')}`).join('<br>');
    let level = 'pass';
    if (mxs.length === 1) level = 'warn';
    return { level,
        label: 'MX 邮件交换记录', rfc: 'RFC 5321 §5',
        msg: `检测到 ${mxs.length} 条 MX 记录${mxs.length === 1 ? '（仅 1 条，建议配置 ≥2 条以实现冗余）' : ''}`,
        detail };
}

async function checkPTR(domain, mxHosts) {
    // PTR is for the mail server IP, not the domain. Try to resolve MX hosts' IPs then check PTR.
    if (!mxHosts || mxHosts.length === 0) {
        return { level: 'warn', label: 'PTR 反向DNS', rfc: 'RFC 1912 §2.1',
            msg: '无法检测 PTR（未配置 MX 或 MX 主机不可解析）。PTR 记录对邮件发送信誉至关重要，缺失会导致被多数接收服务器拒收或标记为垃圾邮件。',
            detail: '<p>ISP 或云服务器提供商负责配置 PTR 记录（需提交工单），PTR 应指向邮件服务器的主机名，而非直接指向域名。例如：<code>1.2.3.4 → mail.example.com</code>（RFC 1912 §2.1）。</p>' };
    }
    // Try to resolve first MX host's IP, then check PTR
    try {
        const firstMX = mxHosts[0];
        const aResult = await dnsQuery(firstMX, 'A');
        if (aResult.status === 0 && aResult.answers.length > 0) {
            const ip = aResult.answers[0].data;
            // Google DoH doesn't natively do PTR via /resolve, use reverse lookup
            const ptrName = ip.split('.').reverse().join('.') + '.in-addr.arpa';
            const ptrResult = await dnsQuery(ptrName, 'PTR');
            if (ptrResult.status === 0 && ptrResult.answers.length > 0) {
                const ptrData = ptrResult.answers[0].data.replace(/\.$/, '');
                return {
                    level: 'pass', label: 'PTR 反向DNS', rfc: 'RFC 1912 §2.1',
                    msg: `PTR 记录: ${ptrData}`,
                    detail: `IP ${ip} → ${ptrData}`
                };
            }
            return {
                level: 'fail', label: 'PTR 反向DNS', rfc: 'RFC 1912 §2.1',
                msg: `MX 主机 ${firstMX} (IP: ${ip}) 没有 PTR 记录。许多邮件服务器会拒绝来自无 PTR 记录 IP 的连接。`,
                detail: `<p>请联系云服务器/ISP 提供商为 IP <code>${ip}</code> 添加 PTR 反向解析，指向 <code>${firstMX}</code>（RFC 1912 §2.1）。</p>`
            };
        }
    } catch(e) {}
    return { level: 'warn', label: 'PTR 反向DNS', rfc: 'RFC 1912 §2.1',
        msg: '无法解析 MX 主机的 A 记录以检测 PTR' };
}

async function checkBIMI(domain) {
    const r = await dnsQuery(`default._bimi.${domain}`, 'TXT');
    const cr = checkResult(r, 'BIMI');
    if (cr.level !== 'pass') return { level: 'warn', label: 'BIMI 品牌邮件标识', rfc: 'RFC 9608',
        msg: '未配置 BIMI（可选功能）。BIMI 可在收件箱中显示品牌 Logo，需 DMARC p=quarantine/reject 为前提。',
        detail: '<p>配置需 DMARC 策略为 quarantine/reject + 已验证的 VMC 证书。格式：<br><code>v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem</code></p>' };
    const data = getDataStr(cr.answers[0]);
    if (data.includes('v=BIMI1')) {
        return { level: 'pass', label: 'BIMI 品牌邮件标识', rfc: 'RFC 9608',
            msg: 'BIMI 已配置',
            detail: `<code>${data.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</code>` };
    }
    return { level: 'warn', label: 'BIMI 品牌邮件标识', rfc: 'RFC 9608',
        msg: '记录存在但格式异常',
        detail: `<code>${data.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</code>` };
}

async function checkMTASTS(domain) {
    const r = await dnsQuery(`_mta-sts.${domain}`, 'TXT');
    const cr = checkResult(r, 'MTA-STS');
    if (cr.level !== 'pass') return { level: 'warn', label: 'MTA-STS 邮件传输代理严格传输安全', rfc: 'RFC 8461',
        msg: '未配置 MTA-STS（增强 SMTP TLS 强制策略）。建议配置以防范降级攻击。',
        detail: '<p>DNS TXT 记录（<code>_mta-sts</code>）：<br><code>v=STSv1; id=2026072101</code><br>还需在 Web 服务器 <code>https://mta-sts.' + domain + '/.well-known/mta-sts.txt</code> 配置策略文件。</p>' };
    const data = getDataStr(cr.answers[0]);
    if (data.includes('v=STSv1')) {
        return { level: 'pass', label: 'MTA-STS 邮件传输代理严格传输安全', rfc: 'RFC 8461',
            msg: 'MTA-STS DNS 记录已配置',
            detail: `<code>${data.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</code>` };
    }
    return { level: 'warn', label: 'MTA-STS', rfc: 'RFC 8461',
        msg: '记录存在但格式异常', detail: `<code>${data.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</code>` };
}

async function checkTLSRPT(domain) {
    const subDom = `_smtp._tls.${domain}`;
    const r = await dnsQuery(subDom, 'TXT');
    const cr = checkResult(r, 'TLS-RPT');
    // Also try alternate location
    if (cr.level !== 'pass') {
        const r2 = await dnsQuery(domain, 'TXT');
        // Actually TLS-RPT is always at _smtp._tls.domain
        return { level: 'warn', label: 'TLS-RPT SMTP TLS 报告', rfc: 'RFC 8460',
            msg: '未配置 TLS-RPT（SMTP TLS 报告）。建议和 MTA-STS 一起配置以监控 TLS 连接问题。',
            detail: `<p>DNS TXT 记录（<code>_smtp._tls</code>）：<br><code>v=TLSRPTv1; rua=mailto:tls@${domain}</code></p>` };
    }
    const data = getDataStr(cr.answers[0]);
    if (data.includes('v=TLSRPTv1')) {
        return { level: 'pass', label: 'TLS-RPT SMTP TLS 报告', rfc: 'RFC 8460',
            msg: 'TLS-RPT 已配置',
            detail: `<code>${data.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</code>` };
    }
    return { level: 'warn', label: 'TLS-RPT', rfc: 'RFC 8460',
        msg: '记录存在但格式异常', detail: `<code>${data.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</code>` };
}

async function checkDNSSEC(domain) {
    // Check DS records at parent (approximate via DNSKEY at domain)
    const r = await dnsQuery(domain, 'DNSKEY');
    const cr = checkResult(r, 'DNSSEC');
    // Actually, we can't easily check DNSSEC via DoH for the parent DS. Better to check DNSKEY + RRSIG.
    // Or check via Cloudflare DoH with dnssec CD flag
    const cfUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=DNSKEY&do=1`;
    try {
        const resp = await fetch(cfUrl, { headers: { 'Accept': 'application/dns-json' } });
        if (!resp.ok) {
            return { level: 'warn', label: 'DNSSEC 域名系统安全扩展', rfc: 'RFC 9364 (BCP 237)',
                msg: '无法检测 DNSSEC 状态（查询失败）' };
        }
        const data = await resp.json();
        if (data.AD === true || data.AuthenticatedData === true) {
            return { level: 'pass', label: 'DNSSEC 域名系统安全扩展', rfc: 'RFC 9364 (BCP 237)',
                msg: 'DNSSEC 已启用（AD 标志已设置）',
                detail: '<p>DNSSEC 为 DNS 记录提供加密签名验证，防止 DNS 劫持和缓存投毒攻击。DANE (RFC 7672) 依赖 DNSSEC 工作。</p>' };
        }
        if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
            return { level: 'pass', label: 'DNSSEC 域名系统安全扩展', rfc: 'RFC 9364 (BCP 237)',
                msg: 'DNSKEY 记录存在（DNSSEC 已配置）',
                detail: '<p>检测到 DNSKEY 记录。完全验证 DNSSEC 需要检查父域 DS 记录和 RRSIG 签名链。</p>' };
        }
        return { level: 'warn', label: 'DNSSEC 域名系统安全扩展', rfc: 'RFC 9364 (BCP 237)',
            msg: '未配置 DNSSEC。建议在域名注册商/托管服务商处启用 DNSSEC。',
            detail: '<p>DNSSEC 是 DANE (RFC 7672) 和 DNS 安全的基础，对于邮件安全至关重要。</p>' };
    } catch(e) {
        return { level: 'warn', label: 'DNSSEC', rfc: 'RFC 9364', msg: '查询失败: ' + e.message };
    }
}

async function checkDANE(domain, mxHosts) {
    if (!mxHosts || mxHosts.length === 0) {
        return { level: 'warn', label: 'DANE DNS 认证命名实体', rfc: 'RFC 7672',
            msg: '无法检测 DANE（未配置 MX 主机）。DANE 通过 TLSA 记录将 TLS 证书与域名绑定，需 DNSSEC 作为前提。',
            detail: '<p>如启用：在 <code>_25._tcp.&lt;mx-host&gt;</code> 添加 TLSA 记录（RFC 7672 §3）</p>' };
    }
    const firstMX = mxHosts[0];
    const r = await dnsQuery(`_25._tcp.${firstMX}`, 'TLSA');
    const cr = checkResult(r, 'DANE TLSA');
    if (cr.level === 'pass') {
        return { level: 'pass', label: 'DANE DNS 认证命名实体', rfc: 'RFC 7672',
            msg: `${firstMX} 已配置 DANE TLSA 记录`,
            detail: cr.answers.map(a => `<code>${getDataStr(a).replace(/</g,'&lt;').replace(/>/g,'&gt;')}</code>`).join('<br>') };
    }
    return { level: 'warn', label: 'DANE DNS 认证命名实体', rfc: 'RFC 7672',
        msg: `MX 主机 ${firstMX} 未配置 DANE TLSA 记录（需要 DNSSEC 前提）`,
        detail: '<p>DANE 通过 TLSA 记录将 TLS 证书指纹发布到 DNSSEC 签名的 DNS 中，防止中间人攻击。配置：<br><code>_25._tcp.&lt;mx-host&gt;  IN  TLSA  3 1 1 &lt;证书SHA256哈希&gt;</code>（RFC 7672 §3.1）</p>' };
}

function renderResult(r) {
    const levelClass = r.level === 'pass' ? 'pass' : (r.level === 'warn' ? 'warn' : 'fail');
    const badge = r.level === 'pass' ? '<span class="rc-badge ok">✅ 正常</span>'
        : (r.level === 'warn' ? '<span class="rc-badge caution">⚠️ 警告</span>'
        : '<span class="rc-badge err">❌ 异常</span>');
    let detail = r.detail || '';
    if (r.selectors) {
        detail += '<div style="margin-top:8px;">';
        for (const s of r.selectors) {
            const sBadge = s.level === 'pass' ? '✅' : '⚠️';
            detail += `<div style="margin-bottom:6px;">${sBadge} <strong>${s.selector}._domainkey</strong>: `;
            if (s.data) {
                const escaped = s.data.replace(/</g,'&lt;').replace(/>/g,'&gt;');
                detail += `<code style="font-size:12px;word-break:break-all;">${escaped.substring(0,100)}${escaped.length > 100 ? '...' : ''}</code>`;
                if (s.note) detail += ` <span style="color:#888;font-size:12px;">${s.note}</span>`;
            } else {
                detail += `<span style="color:#f59e0b;">${s.msg}</span>`;
            }
            detail += '</div>';
        }
        detail += '</div>';
    }
    return `<div class="result-card ${levelClass}">
        <div class="rc-header">
            <span class="rc-label">${r.label}</span>${badge}
        </div>
        <div class="rc-detail">${r.msg || ''}${detail}</div>
        <div class="rc-rfc">📚 ${r.rfc}</div>
    </div>`;
}

function renderSummary(domain, results) {
    const total = results.length;
    const pass = results.filter(r => r.level === 'pass').length;
    const warn = results.filter(r => r.level === 'warn').length;
    const fail = results.filter(r => r.level === 'fail').length;
    const score = total > 0 ? Math.round(pass / total * 100) : 0;

    let scoreText = '';
    if (score >= 80) scoreText = `🟢 ${pass}/${total} 项通过（良好）`;
    else if (score >= 50) scoreText = `🟡 ${pass}/${total} 项通过（需优化）`;
    else scoreText = `🔴 ${pass}/${total} 项通过（需紧急修复）`;

    const bar = document.getElementById('summaryBar');
    bar.style.display = 'block';
    document.getElementById('summaryScore').textContent = scoreText;
    document.getElementById('summaryDomain').textContent = `域名: ${domain} | ✅ ${pass} | ⚠️ ${warn} | ❌ ${fail}`;
}

async function runCheck() {
    const domain = document.getElementById('domainInput').value.trim();
    if (!domain) return;

    const btn = document.getElementById('checkBtn');
    const resultsDiv = document.getElementById('results');
    const errorDiv = document.getElementById('errorMsg');

    btn.disabled = true;
    btn.textContent = '检测中...';
    errorDiv.style.display = 'none';
    resultsDiv.innerHTML = '<div class="status-msg">🔄 正在查询 DNS 记录...</div>';
    document.getElementById('summaryBar').style.display = 'none';

    try {
        // Normalize domain
        let cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*/, '').replace(/^www\./, '').toLowerCase();

        // Get DKIM selectors
        const selectorInput = document.getElementById('dkimSelectors').value.trim();
        const selectors = selectorInput ? selectorInput.split(',').map(s => s.trim()).filter(Boolean) : ['default', 'google'];

        const results = [];

        // Run MX first (to get hosts for PTR/DANE)
        const mxResult = await checkMX(cleanDomain);
        results.push(mxResult);

        // Extract MX hostnames
        let mxHosts = [];
        if (mxResult.detail) {
            const matches = mxResult.detail.match(/→\s*([^\s<]+)/g);
            if (matches) mxHosts = matches.map(m => m.replace(/→\s*/, '').replace(/\.$/, ''));
        }

        // Run remaining checks in parallel batches
        const [spf, dkim, dmarc, ptr, bimi, mtasts, tlsrpt, dnssec] = await Promise.all([
            checkSPF(cleanDomain),
            checkDKIM(cleanDomain, selectors),
            checkDMARC(cleanDomain),
            checkPTR(cleanDomain, mxHosts),
            checkBIMI(cleanDomain),
            checkMTASTS(cleanDomain),
            checkTLSRPT(cleanDomain),
            checkDNSSEC(cleanDomain)
        ]);

        results.push(spf, dkim, dmarc, ptr, bimi, mtasts, tlsrpt, dnssec);

        // DANE (depends on MX result)
        if (mxHosts.length > 0) {
            const dane = await checkDANE(cleanDomain, mxHosts);
            results.push(dane);
        }

        // Render
        resultsDiv.innerHTML = results.map(renderResult).join('');
        renderSummary(cleanDomain, results);
    } catch (e) {
        errorDiv.style.display = 'block';
        errorDiv.textContent = '检测过程出错: ' + e.message;
        resultsDiv.innerHTML = '';
    } finally {
        btn.disabled = false;
        btn.textContent = '开始检测';
    }
}

function quickCheck(domain) {
    document.getElementById('domainInput').value = domain;
    runCheck();
}

// Allow Enter key to trigger check
document.getElementById('domainInput').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') runCheck();
});
