
function generate() {
    const p = document.querySelector('input[name=p]:checked').value;
    const sp = document.querySelector('input[name=sp]:checked').value;
    const adkim = document.querySelector('input[name=adkim]:checked').value;
    const aspf = document.querySelector('input[name=aspf]:checked').value;
    const rua = document.getElementById('rua').value.trim();
    const ruf = document.getElementById('ruf').value.trim();
    const pct = document.getElementById('pct').value.trim();

    const tags = ['v=DMARC1', 'p=' + p];
    const warnings = [];
    if (sp) tags.push('sp=' + sp);
    if (rua) {
        tags.push('rua=mailto:' + rua);
    } else {
        warnings.push('未配置 rua 报告地址，将无法收到聚合报告');
    }
    if (ruf) tags.push('ruf=mailto:' + ruf);
    if (pct) {
        const n = parseInt(pct);
        if (n >= 1 && n <= 100) tags.push('pct=' + n);
        else warnings.push('pct 应为 1-100，已忽略');
    }
    tags.push('adkim=' + adkim, 'aspf=' + aspf);

    const record = tags.join('; ');

    const v = document.getElementById('validation');
    if (warnings.length) {
        v.className = 'validation warn';
        v.style.display = 'block';
        v.innerHTML = '⚠️ ' + warnings.join('<br>⚠️ ');
    } else {
        v.className = 'validation ok';
        v.style.display = 'block';
        v.innerHTML = '✅ 记录结构完整（' + tags.length + ' 个标记），策略 ' + p.toUpperCase() + '。发布后请确认 SPF/DKIM 已正确配置。';
    }

    const out = document.getElementById('output');
    out.style.display = 'block';
    out.innerHTML = `<button class="copy-btn" onclick="copyRec(this)">复制</button><strong>DMARC TXT 记录</strong>（主机名：_dmarc.您的域名）<br><br>${record}`;
}

function copyRec(btn) {
    const text = btn.parentNode.innerText.replace('复制', '').trim();
    navigator.clipboard.writeText(text).then(() => {
        btn.textContent = '已复制 ✓';
        setTimeout(() => btn.textContent = '复制', 1500);
    });
}
