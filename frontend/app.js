const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
let lastResult = null;
let analysisHistory = JSON.parse(sessionStorage.getItem('history') || '[]');

dropZone.addEventListener('dragover', function(e) {
    e.preventDefault();
    dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', function() {
    dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', function(e) {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    var file = e.dataTransfer.files[0];
    if (file) analyzeFile(file);
});

fileInput.addEventListener('change', function() {
    if (fileInput.files[0]) analyzeFile(fileInput.files[0]);
});

function analyzeFile(file) {
    document.getElementById('loading').style.display = 'block';
    document.getElementById('results').style.display = 'none';
    dropZone.style.display = 'none';

    var formData = new FormData();
    formData.append('file', file);

    fetch('/analyze', { method: 'POST', body: formData })
    .then(function(res) {
        if (!res.ok) {
            return res.json().then(function(err) {
                throw new Error(err.detail || 'Error en el servidor');
            });
        }
        return res.json();
    })
    .then(function(data) {
        lastResult = data;
        lastResult.filename = file.name;
        lastResult.timestamp = new Date().toLocaleTimeString();
        analysisHistory.unshift({ filename: file.name, timestamp: lastResult.timestamp, alerts: data.alerts.length, log_type: data.log_type });
        if (analysisHistory.length > 5) analysisHistory.pop();
        sessionStorage.setItem('history', JSON.stringify(analysisHistory));
        renderResults(data);
        renderHistory();
    })
    .catch(function(err) {
        alert('Error: ' + err.message);
        dropZone.style.display = 'block';
    })
    .finally(function() {
        document.getElementById('loading').style.display = 'none';
    });
}

function renderResults(data) {
    document.getElementById('statTotal').textContent = data.total_lines;
    document.getElementById('statSuspicious').textContent = data.suspicious_lines;
    document.getElementById('statAlerts').textContent = data.alerts.length;

    var rate = data.total_lines > 0
        ? ((data.suspicious_lines / data.total_lines) * 100).toFixed(1) + '%'
        : '0%';
    document.getElementById('statRate').textContent = rate;
    document.getElementById('logTypeBadge').textContent = 'Tipo detectado: ' + data.log_type.toUpperCase();
    document.getElementById('summaryBox').textContent = data.summary;

    renderChart(data.alerts);

    var list = document.getElementById('alertsList');
    list.innerHTML = '';

    if (data.alerts.length === 0) {
        list.innerHTML = '<div class="no-alerts">No se detectaron amenazas. Los logs parecen limpios.</div>';
    } else {
        data.alerts.forEach(function(alert) {
            var card = document.createElement('div');
            card.className = 'alert-card';

            var header = document.createElement('div');
            header.className = 'alert-header';

            var badge = document.createElement('span');
            badge.className = 'badge ' + alert.severity;
            badge.textContent = alert.severity;

            var titleEl = document.createElement('span');
            titleEl.className = 'alert-title';
            titleEl.textContent = alert.title;

            header.appendChild(badge);
            header.appendChild(titleEl);

            var desc = document.createElement('div');
            desc.className = 'alert-desc';
            desc.textContent = alert.description;

            var rec = document.createElement('div');
            rec.className = 'recommendation';
            rec.textContent = alert.recommendation;

            card.appendChild(header);
            card.appendChild(desc);
            card.appendChild(rec);
            list.appendChild(card);
        });
    }

    document.getElementById('results').style.display = 'block';

    var btnRow = document.createElement('div');
    btnRow.style.display = 'flex';
    btnRow.style.gap = '1rem';
    btnRow.style.marginTop = '2rem';

    var btnNew = document.createElement('button');
    btnNew.className = 'btn';
    btnNew.textContent = 'Analizar otro archivo';
    btnNew.onclick = function() {
        document.getElementById('results').style.display = 'none';
        dropZone.style.display = 'block';
        fileInput.value = '';
    };

    var btnExport = document.createElement('button');
    btnExport.className = 'btn btn-outline';
    btnExport.textContent = 'Exportar informe PDF';
    btnExport.onclick = exportPDF;

    btnRow.appendChild(btnNew);
    btnRow.appendChild(btnExport);
    document.getElementById('results').appendChild(btnRow);
}

function renderChart(alerts) {
    var counts = { critical: 0, high: 0, medium: 0, low: 0 };
    alerts.forEach(function(a) { if (counts[a.severity] !== undefined) counts[a.severity]++; });

    var max = Math.max(counts.critical, counts.high, counts.medium, counts.low, 1);
    var colors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
    var chartEl = document.getElementById('severityChart');
    chartEl.innerHTML = '';

    Object.keys(counts).forEach(function(sev) {
        var col = document.createElement('div');
        col.style.display = 'flex';
        col.style.flexDirection = 'column';
        col.style.alignItems = 'center';
        col.style.gap = '0.4rem';
        col.style.flex = '1';

        var barWrap = document.createElement('div');
        barWrap.style.height = '80px';
        barWrap.style.display = 'flex';
        barWrap.style.alignItems = 'flex-end';
        barWrap.style.width = '100%';
        barWrap.style.justifyContent = 'center';

        var bar = document.createElement('div');
        var pct = (counts[sev] / max) * 80;
        bar.style.width = '60%';
        bar.style.height = (pct || 4) + 'px';
        bar.style.background = colors[sev];
        bar.style.borderRadius = '4px 4px 0 0';
        bar.style.transition = 'height 0.4s ease';

        var label = document.createElement('div');
        label.style.fontSize = '0.75rem';
        label.style.color = '#94a3b8';
        label.textContent = sev;

        var count = document.createElement('div');
        count.style.fontSize = '0.85rem';
        count.style.fontWeight = '700';
        count.style.color = colors[sev];
        count.textContent = counts[sev];

        barWrap.appendChild(bar);
        col.appendChild(barWrap);
        col.appendChild(count);
        col.appendChild(label);
        chartEl.appendChild(col);
    });
}

function renderHistory() {
    var histEl = document.getElementById('historyList');
    if (!histEl) return;
    histEl.innerHTML = '';
    if (analysisHistory.length === 0) {
        histEl.innerHTML = '<div style="color:#475569;font-size:0.85rem">Sin análisis previos</div>';
        return;
    }
    analysisHistory.forEach(function(item) {
        var row = document.createElement('div');
        row.className = 'history-item';
        row.innerHTML = '<span class="history-file">' + item.filename + '</span>' +
            '<span class="history-type">' + item.log_type.toUpperCase() + '</span>' +
            '<span class="history-alerts">' + item.alerts + ' alertas</span>' +
            '<span class="history-time">' + item.timestamp + '</span>';
        histEl.appendChild(row);
    });
}

function exportPDF() {
    if (!lastResult) return;
    var win = window.open('', '_blank');
    var severityColors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
    var alertsHTML = lastResult.alerts.map(function(a) {
        return '<div style="border:1px solid #ddd;border-radius:8px;padding:12px;margin-bottom:12px">' +
            '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">' +
            '<span style="background:' + severityColors[a.severity] + ';color:white;padding:2px 8px;border-radius:99px;font-size:12px;font-weight:600">' + a.severity.toUpperCase() + '</span>' +
            '<strong>' + a.title + '</strong></div>' +
            '<p style="color:#555;margin-bottom:8px">' + a.description + '</p>' +
            '<p style="color:#7c83f5;border-left:3px solid #7c83f5;padding-left:8px"><strong>Recomendación:</strong> ' + a.recommendation + '</p></div>';
    }).join('');

    win.document.write('<html><head><title>Informe LogAnalyzer AI</title></head><body style="font-family:sans-serif;max-width:800px;margin:0 auto;padding:2rem">' +
        '<h1 style="color:#7c83f5">LogAnalyzer AI - Informe de Análisis</h1>' +
        '<p style="color:#666">Archivo: <strong>' + lastResult.filename + '</strong> | Fecha: ' + new Date().toLocaleString() + '</p>' +
        '<hr>' +
        '<h2>Resumen</h2>' +
        '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:1rem">' +
        '<div style="background:#f8f9fa;padding:12px;border-radius:8px;text-align:center"><div style="font-size:2rem;font-weight:700;color:#7c83f5">' + lastResult.total_lines + '</div><div style="color:#666">Líneas</div></div>' +
        '<div style="background:#f8f9fa;padding:12px;border-radius:8px;text-align:center"><div style="font-size:2rem;font-weight:700;color:#f97316">' + lastResult.suspicious_lines + '</div><div style="color:#666">Sospechosas</div></div>' +
        '<div style="background:#f8f9fa;padding:12px;border-radius:8px;text-align:center"><div style="font-size:2rem;font-weight:700;color:#ef4444">' + lastResult.alerts.length + '</div><div style="color:#666">Alertas</div></div>' +
        '<div style="background:#f8f9fa;padding:12px;border-radius:8px;text-align:center"><div style="font-size:2rem;font-weight:700;color:#7c83f5">' + lastResult.log_type.toUpperCase() + '</div><div style="color:#666">Tipo</div></div>' +
        '</div>' +
        '<h2>Análisis IA</h2><p>' + lastResult.summary + '</p>' +
        '<h2>Alertas Detectadas</h2>' + alertsHTML +
        '<hr><p style="color:#999;font-size:12px">Generado por LogAnalyzer AI - Ciberseguridad Avanzada 2026</p>' +
        '</body></html>');
    win.document.close();
    win.print();
}

renderHistory();