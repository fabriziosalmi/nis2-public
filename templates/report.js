document.addEventListener('DOMContentLoaded', () => {
    // Simple interactions if needed
    console.log("NIS2 Report Loaded");

    function renderCharts(score, findingsMap) {
        if (typeof Chart === 'undefined') {
            console.warn("Chart.js not loaded");
            return;
        }

        // 1. Compliance Score Doughnut
        const scoreCtx = document.getElementById('scoreChart').getContext('2d');
        new Chart(scoreCtx, {
            type: 'doughnut',
            data: {
                labels: ['Compliance', 'Gap'],
                datasets: [{
                    data: [score, 100 - score],
                    backgroundColor: [
                        score >= 80 ? '#10b981' : (score >= 50 ? '#eab308' : '#ef4444'),
                        '#e2e8f0'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                cutout: '75%',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: false }
                }
            }
        });

        // 2. Findings by Severity Bar Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        // findingsMap is {CRITICAL: 2, HIGH: 1, ...}
        const severityLabels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
        const severityData = severityLabels.map(l => findingsMap[l] || 0);

        new Chart(severityCtx, {
            type: 'bar',
            data: {
                labels: severityLabels,
                datasets: [{
                    label: 'Findings',
                    data: severityData,
                    backgroundColor: [
                        '#ef4444', // Critical
                        '#f97316', // High
                        '#eab308', // Medium
                        '#3b82f6'  // Low
                    ],
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { precision: 0 }
                    },
                    x: {
                        grid: { display: false }
                    }
                }
            }
        });
    }

    // Future: Filtering logic
});
