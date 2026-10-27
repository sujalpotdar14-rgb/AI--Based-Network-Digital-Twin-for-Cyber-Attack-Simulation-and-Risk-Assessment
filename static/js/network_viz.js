class NetworkVisualizer {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        
        this.nodes = [];
        this.edges = [];
        this.selectedNode = null;
        
        this.scale = 1.0;
        this.panX = 0;
        this.panY = 0;
        this.isDragging = false;
        this.dragNode = null;
        this.lastMouse = { x: 0, y: 0 };
        
        this.activeParticles = [];
        this.onNodeClick = null;
        
        this.initCanvasSize();
        this.bindEvents();

        if (document.fonts) {
            document.fonts.ready.then(() => this.draw());
        }

        this.animate();
    }

    initCanvasSize() {
        if (!this.canvas || !this.canvas.parentElement) return;
        const rect = this.canvas.parentElement.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) return;
        
        const dpr = window.devicePixelRatio || 1;
        this.canvas.width = rect.width * dpr;
        this.canvas.height = rect.height * dpr;
        this.canvas.style.width = `${rect.width}px`;
        this.canvas.style.height = `${rect.height}px`;
        
        this.ctx.resetTransform();
        this.ctx.scale(dpr, dpr);
        this.draw();
    }

    recenter() {
        this.scale = 1.0;
        this.panX = 0;
        this.panY = 0;
        this.draw();
    }

    setData(topologyData) {
        this.nodes = topologyData.nodes || [];
        this.edges = topologyData.edges || [];
        this.resolveNodePositions();
        this.draw();
    }

    resolveNodePositions() {
        if (!this.nodes || this.nodes.length === 0) return;
        
        const zoneXMap = {
            'WAN': 100,
            'Perimeter': 280,
            'DMZ': 480,
            'Internal': 680,
            'Secure Core': 880,
            'ICS/SCADA': 1080,
            'Cloud': 1080
        };

        const occupiedPositions = [];

        this.nodes.forEach((node, idx) => {
            if (!node.pos || typeof node.pos.x !== 'number' || typeof node.pos.y !== 'number') {
                const base = zoneXMap[node.zone] || 680;
                node.pos = { x: base, y: 140 + (idx * 110) % 400 };
            }

            // De-conflict overlapping nodes (if two nodes are closer than 80px)
            let hasConflict = true;
            let attempts = 0;
            while (hasConflict && attempts < 25) {
                hasConflict = false;
                for (const existing of occupiedPositions) {
                    const dist = Math.hypot(node.pos.x - existing.x, node.pos.y - existing.y);
                    if (dist < 80) {
                        hasConflict = true;
                        node.pos.y += 105;
                        if (node.pos.y > 540) {
                            node.pos.y = 120;
                            node.pos.x += 70;
                        }
                        break;
                    }
                }
                attempts++;
            }
            occupiedPositions.push({ x: node.pos.x, y: node.pos.y });
        });
    }

    bindEvents() {
        window.addEventListener('resize', () => this.initCanvasSize());

        this.canvas.addEventListener('mousedown', (e) => {
            const pos = this.getCanvasCoords(e);
            const clicked = this.findNodeAt(pos.x, pos.y);
            
            if (clicked) {
                this.dragNode = clicked;
                this.selectedNode = clicked;
                if (this.onNodeClick) this.onNodeClick(clicked);
            } else {
                this.isDragging = true;
                this.selectedNode = null;
                if (this.onNodeClick) this.onNodeClick(null);
            }
            this.lastMouse = { x: e.clientX, y: e.clientY };
        });

        this.canvas.addEventListener('mousemove', (e) => {
            const pos = this.getCanvasCoords(e);
            const hoverNode = this.findNodeAt(pos.x, pos.y);
            
            if (this.dragNode) {
                const dx = (e.clientX - this.lastMouse.x) / this.scale;
                const dy = (e.clientY - this.lastMouse.y) / this.scale;
                if (!this.dragNode.pos) this.dragNode.pos = { x: 200, y: 200 };
                this.dragNode.pos.x += dx;
                this.dragNode.pos.y += dy;
                this.lastMouse = { x: e.clientX, y: e.clientY };
            } else if (this.isDragging) {
                this.panX += (e.clientX - this.lastMouse.x);
                this.panY += (e.clientY - this.lastMouse.y);
                this.lastMouse = { x: e.clientX, y: e.clientY };
            }

            this.canvas.style.cursor = hoverNode ? 'pointer' : (this.isDragging ? 'grabbing' : 'default');
        });

        this.canvas.addEventListener('mouseup', () => {
            this.dragNode = null;
            this.isDragging = false;
        });

        this.canvas.addEventListener('mouseleave', () => {
            this.dragNode = null;
            this.isDragging = false;
        });

        this.canvas.addEventListener('wheel', (e) => {
            e.preventDefault();
            const zoomFactor = e.deltaY < 0 ? 1.08 : 0.92;
            this.scale = Math.max(0.4, Math.min(2.5, this.scale * zoomFactor));
            this.draw();
        });
    }

    getCanvasCoords(e) {
        const rect = this.canvas.getBoundingClientRect();
        const mouseX = e.clientX - rect.left;
        const mouseY = e.clientY - rect.top;
        return {
            x: (mouseX - this.panX) / this.scale,
            y: (mouseY - this.panY) / this.scale
        };
    }

    findNodeAt(x, y) {
        return this.nodes.find(n => {
            const nx = n.pos ? n.pos.x : 200;
            const ny = n.pos ? n.pos.y : 200;
            const dist = Math.hypot(x - nx, y - ny);
            return dist <= 30;
        });
    }

    triggerPacketParticles(packetTraces) {
        if (!packetTraces) return;
        packetTraces.forEach(trace => {
            const src = this.nodes.find(n => n.id === trace.from);
            const dst = this.nodes.find(n => n.id === trace.to);
            if (src && dst) {
                for (let i = 0; i < 6; i++) {
                    this.activeParticles.push({
                        startX: src.pos ? src.pos.x : 200,
                        startY: src.pos ? src.pos.y : 200,
                        endX: dst.pos ? dst.pos.x : 200,
                        endY: dst.pos ? dst.pos.y : 200,
                        progress: Math.random() * 0.2,
                        speed: 0.015 + Math.random() * 0.015,
                        color: trace.color || '#FF3366'
                    });
                }
            }
        });
    }

    animate() {
        this.draw();
        requestAnimationFrame(() => this.animate());
    }

    roundRect(x, y, w, h, r) {
        if (w < 2 * r) r = w / 2;
        if (h < 2 * r) r = h / 2;
        this.ctx.beginPath();
        this.ctx.moveTo(x + r, y);
        this.ctx.arcTo(x + w, y, x + w, y + h, r);
        this.ctx.arcTo(x + w, y + h, x, y + h, r);
        this.ctx.arcTo(x, y + h, x, y, r);
        this.ctx.arcTo(x, y, x + w, y, r);
        this.ctx.closePath();
    }

    drawNodeLabel(node, x, y) {
        const rawName = node.name || 'Unnamed Node';
        const words = rawName.split(' ');
        const lines = [];
        let currentLine = '';

        words.forEach(word => {
            if ((currentLine + ' ' + word).trim().length <= 16) {
                currentLine = (currentLine + ' ' + word).trim();
            } else {
                if (currentLine) lines.push(currentLine);
                currentLine = word;
            }
        });
        if (currentLine) lines.push(currentLine);

        if (lines.length > 2) {
            lines[1] = lines.slice(1).join(' ');
            lines.length = 2;
        }

        const ipText = node.ip || '';
        const nameFont = '600 11px Inter, sans-serif';
        const ipFont = '400 10px "JetBrains Mono", monospace';

        this.ctx.font = nameFont;
        let maxTextWidth = 0;
        lines.forEach(l => {
            const w = this.ctx.measureText(l).width;
            if (w > maxTextWidth) maxTextWidth = w;
        });

        this.ctx.font = ipFont;
        const ipWidth = this.ctx.measureText(ipText).width;
        if (ipWidth > maxTextWidth) maxTextWidth = ipWidth;

        const boxWidth = Math.max(90, maxTextWidth + 14);
        const lineHeight = 13;
        const boxHeight = (lines.length * lineHeight) + (ipText ? 15 : 4) + 6;
        const boxX = x - boxWidth / 2;
        const boxY = y + 32;

        this.ctx.save();
        
        // Background card pill
        this.roundRect(boxX, boxY, boxWidth, boxHeight, 6);
        this.ctx.fillStyle = 'rgba(10, 15, 26, 0.92)';
        this.ctx.strokeStyle = (this.selectedNode === node) ? 'rgba(0, 230, 118, 0.8)' : 'rgba(255, 255, 255, 0.12)';
        this.ctx.lineWidth = 1;
        this.ctx.fill();
        this.ctx.stroke();

        // Render node title lines
        this.ctx.textAlign = 'center';
        this.ctx.textBaseline = 'top';
        this.ctx.font = nameFont;
        this.ctx.fillStyle = '#F8FAFC';

        let textY = boxY + 5;
        lines.forEach(l => {
            this.ctx.fillText(l, x, textY);
            textY += lineHeight;
        });

        // Render IP address line
        if (ipText) {
            this.ctx.font = ipFont;
            this.ctx.fillStyle = '#94A3B8';
            this.ctx.fillText(ipText, x, textY + 2);
        }

        this.ctx.restore();
    }

    draw() {
        if (!this.canvas || !this.ctx) return;
        const dpr = window.devicePixelRatio || 1;
        const w = this.canvas.width / dpr;
        const h = this.canvas.height / dpr;
        
        this.ctx.clearRect(0, 0, w, h);
        
        this.ctx.save();
        this.ctx.translate(this.panX, this.panY);
        this.ctx.scale(this.scale, this.scale);

        // 1. Draw Edges
        this.edges.forEach(edge => {
            const src = this.nodes.find(n => n.id === edge.source);
            const dst = this.nodes.find(n => n.id === edge.target);
            if (src && dst) {
                const sx = src.pos ? src.pos.x : 200;
                const sy = src.pos ? src.pos.y : 200;
                const dx = dst.pos ? dst.pos.x : 200;
                const dy = dst.pos ? dst.pos.y : 200;

                this.ctx.beginPath();
                this.ctx.moveTo(sx, sy);
                this.ctx.lineTo(dx, dy);
                this.ctx.strokeStyle = (src.status === 'compromised' || dst.status === 'compromised') 
                    ? 'rgba(255, 51, 102, 0.4)' 
                    : (src.status === 'under_attack' || dst.status === 'under_attack')
                    ? 'rgba(255, 193, 7, 0.4)'
                    : 'rgba(255, 255, 255, 0.15)';
                this.ctx.lineWidth = 2;
                this.ctx.stroke();
            }
        });

        // 2. Draw Packet Particles
        for (let i = this.activeParticles.length - 1; i >= 0; i--) {
            const p = this.activeParticles[i];
            p.progress += p.speed;
            
            const currX = p.startX + (p.endX - p.startX) * p.progress;
            const currY = p.startY + (p.endY - p.startY) * p.progress;
            
            this.ctx.beginPath();
            this.ctx.arc(currX, currY, 4, 0, Math.PI * 2);
            this.ctx.fillStyle = p.color;
            this.ctx.shadowColor = p.color;
            this.ctx.shadowBlur = 10;
            this.ctx.fill();
            this.ctx.shadowBlur = 0;
            
            if (p.progress >= 1.0) {
                this.activeParticles.splice(i, 1);
            }
        }

        // 3. Draw Nodes
        this.nodes.forEach(node => {
            const x = node.pos ? node.pos.x : 200;
            const y = node.pos ? node.pos.y : 200;
            
            // Outer Halo Ring by Status
            let statusColor = '#00E676';
            if (node.status === 'under_attack') statusColor = '#FFC107';
            else if (node.status === 'compromised') statusColor = '#FF3366';
            else if (node.status === 'isolated') statusColor = '#00B0FF';
            else if (node.status === 'shielded') statusColor = '#B388FF';

            this.ctx.beginPath();
            this.ctx.arc(x, y, 26, 0, Math.PI * 2);
            this.ctx.fillStyle = 'rgba(18, 24, 38, 0.95)';
            this.ctx.strokeStyle = statusColor;
            this.ctx.lineWidth = (this.selectedNode === node) ? 4 : 2;
            this.ctx.shadowColor = statusColor;
            this.ctx.shadowBlur = (node.status === 'compromised') ? 22 : 8;
            this.ctx.fill();
            this.ctx.stroke();
            this.ctx.shadowBlur = 0;

            // FontAwesome Icon rendering
            this.ctx.fillStyle = '#FFFFFF';
            this.ctx.font = '900 14px "Font Awesome 6 Free", "FontAwesome", sans-serif';
            this.ctx.textAlign = 'center';
            this.ctx.textBaseline = 'middle';
            
            let iconCode = '\uf233'; // server default
            if (node.type === 'router') iconCode = '\uf6ff';
            else if (node.type === 'firewall') iconCode = '\uf3ed';
            else if (node.type === 'database') iconCode = '\uf1c0';
            else if (node.type === 'workstation') iconCode = '\uf108';
            else if (node.type === 'scada') iconCode = '\uf2db';
            else if (node.type === 'cloud') iconCode = '\uf0c2';
            
            this.ctx.fillText(iconCode, x, y);

            // Render structured node label card underneath
            this.drawNodeLabel(node, x, y);
        });

        this.ctx.restore();
    }
}
