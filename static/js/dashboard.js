document.addEventListener('DOMContentLoaded', function () {
    // ==========================================
    // 1. Quick IOC Lookup Form Handler
    // ==========================================
    const quickIocForm = document.getElementById('quick-ioc-form');
    
    if (quickIocForm) {
        quickIocForm.addEventListener('submit', function (e) {
            e.preventDefault();
            
            const input = this.querySelector('input[name="ioc"]');
            const iocValue = input ? input.value.trim() : '';

            if (!iocValue) {
                alert('กรุณากรอก IOC (IP, Domain, URL, Hash หรือ Email)');
                return;
            }

            // Redirect ไปยังหน้าวิเคราะห์ IOC พร้อมส่ง Parameter 'q' หรือ 'ioc'
            window.location.href = `/analysis/ioc?q=${encodeURIComponent(iocValue)}`;
        });
    }

    // ==========================================
    // 2. Verdict Distribution Chart (Chart.js)
    // ==========================================
    const chartCanvas = document.getElementById('verdict-dist-chart');
    
    if (chartCanvas && typeof Chart !== 'undefined') {
        // ดึงค่าสถิติจาก Stat Cards บนหน้าจอ
        const maliciousCount = parseInt(document.getElementById('stat-malicious')?.textContent || '0', 10);
        const suspiciousCount = parseInt(document.getElementById('stat-suspicious')?.textContent || '0', 10);
        const cleanCount = parseInt(document.getElementById('stat-clean')?.textContent || '0', 10);

        const ctx = chartCanvas.getContext('2d');
        
        // สร้าง Doughnut Chart
        window.verdictChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Malicious', 'Suspicious', 'Clean'],
                datasets: [{
                    data: [maliciousCount, suspiciousCount, cleanCount],
                    backgroundColor: [
                        '#dc3545', // Danger (Red)
                        '#ffc107', // Warning (Yellow)
                        '#198754'  // Success (Green)
                    ],
                    borderWidth: 2,
                    borderColor: '#ffffff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            boxWidth: 12,
                            padding: 15
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function (context) {
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const value = context.raw;
                                const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                                return ` ${context.label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                },
                cutout: '70%' // ทำวงแหวนให้ดูโปร่งสไตล์ Dashboard Modern
            }
        });
    }

    // ==========================================
    // 3. Dynamic Stats & Polling Update (API)
    // ==========================================
    // ฟังก์ชันสำหรับสั่งอัปเดตข้อมูลบนหน้า Dashboard โดยไม่ต้อง Reload หน้าเว็บ
    async function fetchDashboardData() {
        try {
            const response = await fetch('/api/dashboard/stats');
            if (!response.ok) return;

            const data = await response.json();

            // อัปเดต Stat Cards
            if (data.stats) {
                document.getElementById('stat-total-analyses').textContent = data.stats.total_analyses || 0;
                document.getElementById('stat-malicious').textContent = data.stats.malicious_count || 0;
                document.getElementById('stat-suspicious').textContent = data.stats.suspicious_count || 0;
                document.getElementById('stat-clean').textContent = data.stats.clean_count || 0;

                // อัปเดต Chart ข้อมูลใหม่
                if (window.verdictChart) {
                    window.verdictChart.data.datasets[0].data = [
                        data.stats.malicious_count || 0,
                        data.stats.suspicious_count || 0,
                        data.stats.clean_count || 0
                    ];
                    window.verdictChart.update();
                }
            }
        } catch (error) {
            console.error('Error fetching dashboard stats:', error);
        }
    }

    // ตั้งเวลาให้ดึงข้อมูลอัปเดตอัตโนมัติทุกๆ 30 วินาที (ถ้าต้องการ)
    // setInterval(fetchDashboardData, 30000);
});