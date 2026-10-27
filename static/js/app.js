document.addEventListener('DOMContentLoaded', () => {
    let viz = null;
    let currentTopology = null;

    // 1. Tab Navigation Setup
    const navBtns = document.querySelectorAll('.nav-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    navBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');
            navBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            const activeEl = document.getElementById(targetTab);
            if (activeEl) activeEl.classList.add('active');

            if (targetTab === 'tab-topology') {
                setTimeout(() => {
                    if (viz) viz.initCanvasSize();
                }, 50);
            } else if (targetTab === 'tab-analytics') {
                fetchMetrics();
                fetchMLMetadata();
                setTimeout(() => {
                    if (typeof resizeCharts === 'function') resizeCharts();
                }, 50);
            } else if (targetTab === 'tab-playbooks') {
                loadPlaybooks();
            }
        });
    });

    // 2. Initialize Visualizer & Canvas
    viz = new NetworkVisualizer('topologyCanvas');
    viz.onNodeClick = (node) => renderNodeInspector(node);

    // Recenter Button
    const btnRecenter = document.getElementById('btn-recenter');
    if (btnRecenter) {
        btnRecenter.addEventListener('click', () => {
            if (viz) viz.recenter();
        });
    }

    // 3. Fetch Topology Data
    async function loadTopology() {
        try {
            const res = await fetch('/api/topology');
            const data = await res.json();
            currentTopology = data;
            viz.setData(data);
            populateTargetNodeSelect(data.nodes);
            populateAssetTable(data.nodes);
        } catch (err) {
            console.error('Failed to load topology:', err);
        }
    }

    // 4. Fetch Metrics
    async function fetchMetrics() {
        try {
            const res = await fetch('/api/metrics');
            const metrics = await res.json();

            // Header Elements
            const riskHeader = document.getElementById('risk-score-header');
            const riskLarge = document.getElementById('risk-score-large');
            const threatBadge = document.getElementById('threat-level-badge');
            const blastHeader = document.getElementById('blast-radius-header');
            const riskDesc = document.getElementById('risk-description');

            const score = metrics.network_risk_score;
            if (riskHeader) riskHeader.textContent = score;
            if (riskLarge) riskLarge.textContent = score;
            if (blastHeader) blastHeader.textContent = `${metrics.blast_radius_percent}%`;

            if (riskDesc) {
                if (score <= 25) {
                    riskDesc.textContent = 'Network state is currently baseline healthy with low vulnerability exposure.';
                } else if (score <= 55) {
                    riskDesc.textContent = 'Moderate security risk detected. Vulnerabilities or active attacks present.';
                } else if (score <= 80) {
                    riskDesc.textContent = 'HIGH RISK: Critical threat propagation across internal assets!';
                } else {
                    riskDesc.textContent = 'CRITICAL ALERT: Severe cyber outbreak! Immediate automated mitigation required.';
                }
            }

            if (threatBadge) {
                const badgeClass = metrics.threat_level === 'LOW' ? 'green' : metrics.threat_level === 'MEDIUM' ? 'amber' : 'red';
                threatBadge.className = `status-badge badge-${badgeClass}`;
                threatBadge.innerHTML = `<i class="fa-solid fa-shield-halved"></i> ${metrics.threat_level}`;
            }

            if (metrics.risk_history && typeof updateRiskHistoryChart === 'function') {
                updateRiskHistoryChart(metrics.risk_history);
            }
        } catch (err) {
            console.error('Failed to fetch metrics:', err);
        }
    }

    // 5. Fetch ML Model Metadata
    async function fetchMLMetadata() {
        try {
            const res = await fetch('/api/ml/metadata');
            const metadata = await res.json();
            if (typeof updateMLMetadataCharts === 'function') {
                updateMLMetadataCharts(metadata);
            }
        } catch (err) {
            console.error('Failed to fetch ML metadata:', err);
        }
    }

    // 6. Populate Target Node Select dropdown
    function populateTargetNodeSelect(nodes) {
        const select = document.getElementById('target-node-select');
        if (!select || !nodes) return;
        select.innerHTML = '';
        nodes.forEach(n => {
            const opt = document.createElement('option');
            opt.value = n.id;
            opt.textContent = `${n.name} (${n.ip}) - CVSS ${n.cvss_score}`;
            select.appendChild(opt);
        });
    }

    // 7. Node Inspector Panel Renderer
    function renderNodeInspector(node) {
        const container = document.getElementById('inspector-content');
        if (!container) return;

        if (!node) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fa-solid fa-mouse-pointer"></i>
                    <p>Click any node on the graph to inspect detailed telemetry, open ports, CVSS vulnerabilities, and graph centrality.</p>
                </div>`;
            return;
        }

        const cvesHtml = (node.cve_list || []).map(cve => `<span class="cve-pill">${cve.id} (CVSS ${cve.cvss})</span>`).join('');
        const statusClass = node.status === 'healthy' ? 'green' : node.status === 'compromised' ? 'red' : 'amber';

        container.innerHTML = `
            <div class="node-detail-section">
                <div class="node-title-box">
                    <h4>${node.name}</h4>
                    <p>${node.ip} | Zone: ${node.zone}</p>
                </div>

                <div class="detail-row">
                    <span class="detail-label">Status</span>
                    <span class="detail-value text-${statusClass}">${(node.status || 'healthy').toUpperCase()}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Asset Type</span>
                    <span class="detail-value">${(node.type || 'N/A').toUpperCase()}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">OS / Platform</span>
                    <span class="detail-value">${node.os || 'N/A'}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Open Ports</span>
                    <span class="detail-value">${(node.open_ports || []).join(', ')}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">CVSS Risk</span>
                    <span class="detail-value text-red">${node.cvss_score || '0.0'}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Asset Criticality</span>
                    <span class="detail-value">${node.asset_criticality || '1.0'} / 5.0</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Betweenness Centrality</span>
                    <span class="detail-value">${node.betweenness_centrality || '0.0'}</span>
                </div>

                <h4 style="margin-top:10px; font-size:12px; color:var(--primary-cyan);">Active Telemetry Feeds</h4>
                <div class="detail-row"><span class="detail-label">CPU Utilization</span><span class="detail-value">${node.telemetry?.cpu_utilization || 20}%</span></div>
                <div class="detail-row"><span class="detail-label">RAM Usage</span><span class="detail-value">${node.telemetry?.ram_utilization || 30}%</span></div>
                <div class="detail-row"><span class="detail-label">Bandwidth</span><span class="detail-value">${node.telemetry?.bandwidth_mbps || 100} Mbps</span></div>

                <h4 style="margin-top:10px; font-size:12px; color:var(--primary-cyan);">Vulnerabilities</h4>
                ${cvesHtml || '<p class="text-muted" style="font-size:11px;">No critical CVEs logged.</p>'}
            </div>`;
    }

    // 8. Attack Simulation Submission
    const simForm = document.getElementById('sim-form');
    if (simForm) {
        simForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const attackType = document.getElementById('attack-type-select').value;
            const targetNode = document.getElementById('target-node-select').value;
            const intensity = document.getElementById('sim-intensity').value;

            const termLog = document.getElementById('terminal-log');
            appendLog(termLog, `[SIM_TRIGGER] Executing ${attackType} on node ${targetNode}...`, 'sys-line');

            // Reset Kill chain highlight
            document.querySelectorAll('.kc-step').forEach(s => s.classList.remove('active'));

            try {
                const res = await fetch('/api/simulate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ attack_type: attackType, target_node: targetNode, intensity: intensity })
                });

                const data = await res.json();
                if (data.success) {
                    // Trigger MITRE ATT&CK step animations
                    (data.stages || []).forEach((st, idx) => {
                        setTimeout(() => {
                            const stepEl = document.getElementById(`kc-step-${st.stage}`);
                            if (stepEl) stepEl.classList.add('active');
                        }, idx * 600);
                    });

                    // Append logs
                    (data.logs || []).forEach(log => {
                        appendLog(termLog, log, log.includes('IMPACT') ? 'impact-line' : log.includes('RECON') ? 'recon-line' : 'priv-line');
                    });

                    // Trigger packet animation on canvas
                    if (viz) viz.triggerPacketParticles(data.packet_traces);

                    // Reload topology & metrics
                    await loadTopology();
                    await fetchMetrics();
                }
            } catch (err) {
                console.error('Simulation error:', err);
            }
        });
    }

    function appendLog(container, text, className) {
        if (!container) return;
        const line = document.createElement('div');
        line.className = `log-line ${className}`;
        line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
        container.appendChild(line);
        container.scrollTop = container.scrollHeight;
    }

    // 9. Reset Network State Button
    const btnReset = document.getElementById('btn-reset-net');
    if (btnReset) {
        btnReset.addEventListener('click', async () => {
            await fetch('/api/topology/reset', { method: 'POST' });
            await loadTopology();
            await fetchMetrics();
            appendLog(document.getElementById('terminal-log'), '[SYS_RESET] Digital twin network topology reset to baseline healthy.', 'sys-line');
        });
    }

    // 10. Refresh Defense Playbooks Button
    const btnRefreshPb = document.getElementById('btn-refresh-playbooks');
    if (btnRefreshPb) {
        btnRefreshPb.addEventListener('click', () => {
            loadPlaybooks();
        });
    }

    // 11. Defense Playbooks Loader
    async function loadPlaybooks() {
        const container = document.getElementById('playbooks-container');
        if (!container) return;
        try {
            const res = await fetch('/api/playbooks');
            const data = await res.json();
            const pbs = data.playbooks || [];

            if (pbs.length === 0) {
                container.innerHTML = '<div class="glass-card" style="padding:20px; grid-column: 1/-1;"><p class="text-muted">No high-risk mitigation playbooks currently required. Network state healthy.</p></div>';
                return;
            }

            container.innerHTML = pbs.map(pb => `
                <div class="playbook-card glass-card ${pb.severity}">
                    <div class="pb-header">
                        <span class="pb-title">${pb.title}</span>
                        <span class="status-badge badge-${pb.severity === 'CRITICAL' ? 'red' : 'amber'}">${pb.severity}</span>
                    </div>
                    <p class="pb-desc">${pb.description}</p>
                    <p style="font-size:11px; color:#00F2FE;">Estimated Risk Drop: -${pb.risk_reduction_estimate} pts</p>
                    <div class="pb-footer">
                        <button class="btn btn-sm btn-secondary btn-whatif" data-action="${pb.action_type}" data-node="${pb.node_id}">Simulate What-If</button>
                        <button class="btn btn-sm btn-primary btn-apply-pb" data-action="${pb.action_type}" data-node="${pb.node_id}">Apply Mitigation</button>
                    </div>
                </div>
            `).join('');

            // Bind buttons
            document.querySelectorAll('.btn-whatif').forEach(b => {
                b.addEventListener('click', async () => {
                    const act = b.getAttribute('data-action');
                    const nid = b.getAttribute('data-node');
                    const res = await fetch('/api/mitigate/what-if', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action_type: act, node_id: nid })
                    });
                    const r = await res.json();
                    alert(`[WHAT-IF SIMULATION]\nInitial Risk: ${r.initial_risk_score}\nPost-Mitigation Risk: ${r.simulated_risk_score}\nRisk Reduction: -${r.risk_score_reduction} pts (${r.percentage_reduction}% drop)`);
                });
            });

            document.querySelectorAll('.btn-apply-pb').forEach(b => {
                b.addEventListener('click', async () => {
                    const act = b.getAttribute('data-action');
                    const nid = b.getAttribute('data-node');
                    const res = await fetch('/api/mitigate', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action_type: act, node_id: nid })
                    });
                    const r = await res.json();
                    if (r.success) {
                        alert(`[MITIGATION APPLIED]\n${r.message}\nRisk Score reduced from ${r.initial_risk_score} -> ${r.post_mitigation_risk_score}`);
                        await loadTopology();
                        await fetchMetrics();
                        loadPlaybooks();
                    }
                });
            });
        } catch (err) {
            console.error('Failed to load playbooks:', err);
        }
    }

    // 12. Asset Manager List & Form
    function populateAssetTable(nodes) {
        const body = document.getElementById('asset-table-body');
        if (!body || !nodes) return;
        body.innerHTML = nodes.map(n => `
            <tr>
                <td><strong>${n.name}</strong></td>
                <td>${n.type}</td>
                <td>${n.zone}</td>
                <td>${n.ip}</td>
                <td class="text-red">${n.cvss_score}</td>
                <td>${n.asset_criticality}</td>
                <td><span class="status-badge badge-${n.status === 'healthy' ? 'green' : 'red'}">${n.status}</span></td>
            </tr>
        `).join('');
    }

    const addAssetForm = document.getElementById('add-asset-form');
    if (addAssetForm) {
        addAssetForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = document.getElementById('asset-name').value;
            const type = document.getElementById('asset-type').value;
            const zone = document.getElementById('asset-zone').value;
            const ip = document.getElementById('asset-ip').value;
            const cvss = parseFloat(document.getElementById('asset-cvss').value);
            const crit = parseFloat(document.getElementById('asset-criticality').value);

            await fetch('/api/topology/node', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: name, type: type, zone: zone, ip: ip, cvss_score: cvss, asset_criticality: crit })
            });

            await loadTopology();
            await fetchMetrics();
            addAssetForm.reset();
            alert(`Node "${name}" successfully added to Digital Twin network.`);
        });
    }

    // 13. AI Model Telemetry Predictor Form
    const aiPredictForm = document.getElementById('ai-predict-form');
    if (aiPredictForm) {
        aiPredictForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const payload = {
                cvss_score: parseFloat(document.getElementById('pred-cvss').value),
                failed_logins: parseInt(document.getElementById('pred-failed-logins').value, 10),
                syn_flag_ratio: parseFloat(document.getElementById('pred-syn-ratio').value),
                error_rate: parseFloat(document.getElementById('pred-error-rate').value),
                packet_length_mean: parseFloat(document.getElementById('pred-pkt-len').value),
                asset_criticality: parseFloat(document.getElementById('pred-crit').value)
            };

            const resultDiv = document.getElementById('ai-predict-result');
            resultDiv.style.display = 'block';
            resultDiv.innerHTML = '<p class="text-muted"><i class="fa-solid fa-spinner fa-spin"></i> Evaluating Machine Learning models...</p>';

            try {
                const res = await fetch('/api/ai/predict', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();

                if (res.ok) {
                    const isNormal = data.predicted_class === 'Normal Telemetry';
                    const badgeColor = isNormal ? 'green' : 'red';
                    
                    let probsHtml = '';
                    if (data.class_probabilities) {
                        probsHtml = Object.entries(data.class_probabilities).map(([cls, prob]) => `
                            <div style="margin-top: 6px;">
                                <div style="display:flex; justify-content:space-between; font-size:11px;">
                                    <span>${cls}</span>
                                    <span>${prob}%</span>
                                </div>
                                <div style="background: rgba(255,255,255,0.1); height: 6px; border-radius: 3px; overflow: hidden; margin-top: 2px;">
                                    <div style="width: ${prob}%; height: 100%; background: ${cls === 'Normal Telemetry' ? '#00E676' : '#FF3366'};"></div>
                                </div>
                            </div>
                        `).join('');
                    }

                    resultDiv.innerHTML = `
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                            <h4 style="font-size:14px; font-weight:700;">AI Model Threat Verdict</h4>
                            <span class="status-badge badge-${badgeColor}">${data.predicted_class}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Isolation Forest Anomaly Score</span>
                            <span class="detail-value text-${data.is_anomaly ? 'red' : 'green'}">${data.anomaly_score} / 100 (${data.is_anomaly ? 'ANOMALOUS TRAFFIC' : 'INLIER NORMAL'})</span>
                        </div>
                        <h4 style="margin-top: 14px; font-size:12px; color: var(--primary-cyan);">Class Probability Distribution</h4>
                        ${probsHtml}
                    `;
                } else {
                    resultDiv.innerHTML = `<p class="text-red">Error: ${data.error || 'Failed to predict'}</p>`;
                }
            } catch (err) {
                console.error('Prediction error:', err);
                resultDiv.innerHTML = '<p class="text-red">Error communicating with ML backend.</p>';
            }
        });
    }

    // 14. AI Security Copilot Chat
    const copilotForm = document.getElementById('copilot-form');
    const copilotInput = document.getElementById('copilot-input');
    const chatBox = document.getElementById('chat-box');

    if (copilotForm) {
        copilotForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const text = copilotInput.value.trim();
            if (!text) return;

            appendChatMsg('user', text);
            copilotInput.value = '';

            try {
                const res = await fetch('/api/ai/copilot', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query: text })
                });
                const data = await res.json();
                appendChatMsg('bot', data.reply);
            } catch (err) {
                appendChatMsg('bot', 'Error communicating with Copilot backend.');
            }
        });

        document.querySelectorAll('.chip-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                copilotInput.value = btn.getAttribute('data-query');
                copilotForm.dispatchEvent(new Event('submit'));
            });
        });
    }

    function appendChatMsg(sender, message) {
        if (!chatBox) return;
        const msgDiv = document.createElement('div');
        msgDiv.className = `chat-msg ${sender}-msg`;
        msgDiv.innerHTML = `
            <div class="msg-avatar"><i class="fa-solid fa-${sender === 'user' ? 'user' : 'shield-cat'}"></i></div>
            <div class="msg-bubble">${message}</div>
        `;
        chatBox.appendChild(msgDiv);
        chatBox.scrollTop = chatBox.scrollHeight;
    }

    // Initial Load & Charts
    if (typeof initCharts === 'function') initCharts();
    loadTopology();
    fetchMetrics();
    fetchMLMetadata();
    setInterval(fetchMetrics, 5000);
});
