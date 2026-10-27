let riskHistoryChartInstance = null;
let threatDistributionChartInstance = null;
let featureImportanceChartInstance = null;

function initCharts() {
    // 1. Risk Score Timeline Chart
    const elHistory = document.getElementById('riskHistoryChart');
    if (elHistory) {
        if (riskHistoryChartInstance) riskHistoryChartInstance.destroy();
        riskHistoryChartInstance = new Chart(elHistory.getContext('2d'), {
            type: 'line',
            data: {
                labels: ['0s', '5s', '10s', '15s', '20s', '25s'],
                datasets: [{
                    label: 'Network Risk Score',
                    data: [14.2, 14.2, 14.2, 14.2, 14.2, 14.2],
                    borderColor: '#00F2FE',
                    backgroundColor: 'rgba(0, 242, 254, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                    pointBackgroundColor: '#00F2FE'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { min: 0, max: 100, grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#94A3B8' } },
                    x: { grid: { display: false }, ticks: { color: '#94A3B8' } }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    // 2. Threat Distribution Pie Chart
    const elThreat = document.getElementById('threatDistributionChart');
    if (elThreat) {
        if (threatDistributionChartInstance) threatDistributionChartInstance.destroy();
        threatDistributionChartInstance = new Chart(elThreat.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['Normal', 'DDoS SYN Flood', 'Ransomware', 'MitM', 'SSH Brute', 'SQLi/RCE', 'Port Scan'],
                datasets: [{
                    data: [45, 12, 8, 8, 10, 7, 10],
                    backgroundColor: [
                        '#00E676', '#FF3366', '#7F00FF', '#FF9800', '#FFC107', '#00B0FF', '#B388FF'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'right', labels: { color: '#F8FAFC', font: { size: 11 } } }
                }
            }
        });
    }

    // 3. Feature Importance Bar Chart
    const elFeature = document.getElementById('featureImportanceChart');
    if (elFeature) {
        if (featureImportanceChartInstance) featureImportanceChartInstance.destroy();
        featureImportanceChartInstance = new Chart(elFeature.getContext('2d'), {
            type: 'bar',
            data: {
                labels: ['CVSS Score', 'Failed Logins', 'SYN Ratio', 'Error Rate', 'Packet Len', 'Centrality'],
                datasets: [{
                    label: 'Importance Weight',
                    data: [0.28, 0.22, 0.18, 0.14, 0.10, 0.08],
                    backgroundColor: '#7F00FF',
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#94A3B8' } },
                    y: { grid: { display: false }, ticks: { color: '#94A3B8' } }
                },
                plugins: { legend: { display: false } }
            }
        });
    }
}

function updateRiskHistoryChart(riskHistoryData) {
    if (!riskHistoryChartInstance || !riskHistoryData) return;
    riskHistoryChartInstance.data.labels = riskHistoryData.map(d => d.timestamp || 'T');
    riskHistoryChartInstance.data.datasets[0].data = riskHistoryData.map(d => d.score);
    riskHistoryChartInstance.update();
}

function updateMLMetadataCharts(metadata) {
    if (!metadata || !featureImportanceChartInstance) return;
    if (metadata.feature_importances) {
        const feats = Object.keys(metadata.feature_importances);
        const imps = Object.values(metadata.feature_importances);
        featureImportanceChartInstance.data.labels = feats;
        featureImportanceChartInstance.data.datasets[0].data = imps;
        featureImportanceChartInstance.update();
    }
}

function resizeCharts() {
    if (riskHistoryChartInstance) riskHistoryChartInstance.resize();
    if (threatDistributionChartInstance) threatDistributionChartInstance.resize();
    if (featureImportanceChartInstance) featureImportanceChartInstance.resize();
}
