// Dashboard JavaScript for Cloud Security Automation
class SecurityDashboard {
    constructor() {
        this.charts = {};
        this.currentTab = 'overview';
        this.refreshInterval = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadDashboardData();
        this.startAutoRefresh();
    }

    setupEventListeners() {
        // Tab navigation
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                this.switchTab(e.target.dataset.tab);
            });
        });

        // Time range selector
        document.getElementById('timeRange').addEventListener('change', (e) => {
            this.loadDashboardData(e.target.value);
        });

        // Filters
        document.getElementById('severityFilter')?.addEventListener('change', () => {
            this.filterFindings();
        });

        document.getElementById('statusFilter')?.addEventListener('change', () => {
            this.filterFindings();
        });

        document.getElementById('searchFilter')?.addEventListener('input', () => {
            this.filterFindings();
        });

        // Framework filter
        document.getElementById('frameworkFilter')?.addEventListener('change', (e) => {
            this.loadComplianceData(e.target.value);
        });

        // Threat time range
        document.getElementById('threatTimeRange')?.addEventListener('change', (e) => {
            this.loadThreatIntelligence(e.target.value);
        });

        // Resource filters
        document.getElementById('resourceTypeFilter')?.addEventListener('change', () => {
            this.filterResources();
        });

        document.getElementById('resourceRegionFilter')?.addEventListener('change', () => {
            this.filterResources();
        });

        // Analytics time range
        document.getElementById('analyticsTimeRange')?.addEventListener('change', (e) => {
            this.loadAnalyticsData(e.target.value);
        });

        // Chart controls
        document.querySelectorAll('.chart-control').forEach(control => {
            control.addEventListener('click', (e) => {
                this.updateChartPeriod(e.target.dataset.period);
            });
        });
    }

    switchTab(tabName) {
        // Update active tab
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update active content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(tabName).classList.add('active');

        this.currentTab = tabName;

        // Load tab-specific data
        this.loadTabData(tabName);
    }

    loadTabData(tabName) {
        switch (tabName) {
            case 'overview':
                this.loadDashboardData();
                break;
            case 'findings':
                this.loadFindings();
                break;
            case 'compliance':
                this.loadComplianceData();
                break;
            case 'threats':
                this.loadThreatIntelligence();
                break;
            case 'resources':
                this.loadResourceInventory();
                break;
            case 'analytics':
                this.loadAnalyticsData();
                break;
        }
    }

    async loadDashboardData(days = 30) {
        try {
            this.showLoading();
            
            const response = await fetch(`/api/analytics/dashboard-stats?days=${days}`);
            const data = await response.json();

            if (data.success) {
                this.updateOverviewMetrics(data.data);
                this.updateOverviewCharts(data.data);
                this.updateRecentActivities(data.data);
            } else {
                this.showNotification('Error loading dashboard data', 'error');
            }
        } catch (error) {
            console.error('Error loading dashboard data:', error);
            this.showNotification('Failed to load dashboard data', 'error');
        } finally {
            this.hideLoading();
        }
    }

    updateOverviewMetrics(data) {
        const overview = data.overview;
        
        // Update key metrics
        document.getElementById('securityScore').textContent = overview.security_score || '--';
        document.getElementById('totalFindings').textContent = overview.total_findings || '--';
        document.getElementById('totalResources').textContent = overview.total_resources || '--';
        
        // Calculate compliance rate
        const complianceStatus = data.compliance_status;
        const totalCompliance = Object.values(complianceStatus).reduce((a, b) => a + b, 0);
        const complianceRate = totalCompliance > 0 ? 
            Math.round((complianceStatus.compliant || 0) / totalCompliance * 100) : 0;
        document.getElementById('complianceRate').textContent = complianceRate;

        // Update severity breakdown
        const severity = data.severity_distribution;
        document.getElementById('criticalFindings').textContent = severity.critical || 0;
        document.getElementById('highFindings').textContent = severity.high || 0;
        document.getElementById('mediumFindings').textContent = severity.medium || 0;
        document.getElementById('lowFindings').textContent = severity.low || 0;

        // Update last updated time
        document.getElementById('lastUpdated').textContent = new Date().toLocaleString();
    }

    updateOverviewCharts(data) {
        // Findings Trend Chart
        this.createFindingsTrendChart(data.recent_findings_trend);
        
        // Severity Distribution Chart
        this.createSeverityChart(data.severity_distribution);
        
        // Regional Distribution Chart
        this.createRegionalChart(data.regional_distribution);
        
        // Risk Trend Chart
        this.createRiskTrendChart(data.risk_trend);
    }

    createFindingsTrendChart(trendData) {
        const ctx = document.getElementById('findingsTrendChart');
        if (!ctx) return;

        if (this.charts.findingsTrend) {
            this.charts.findingsTrend.destroy();
        }

        this.charts.findingsTrend = new Chart(ctx, {
            type: 'line',
            data: {
                labels: trendData.map(d => new Date(d.date).toLocaleDateString()),
                datasets: [{
                    label: 'New Findings',
                    data: trendData.map(d => d.count),
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                }
            }
        });
    }

    createSeverityChart(severityData) {
        const ctx = document.getElementById('severityChart');
        if (!ctx) return;

        if (this.charts.severity) {
            this.charts.severity.destroy();
        }

        const data = [
            severityData.critical || 0,
            severityData.high || 0,
            severityData.medium || 0,
            severityData.low || 0
        ];

        this.charts.severity = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: data,
                    backgroundColor: [
                        '#dc2626',
                        '#ea580c',
                        '#d97706',
                        '#65a30d'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }

    createRegionalChart(regionalData) {
        const ctx = document.getElementById('regionalChart');
        if (!ctx) return;

        if (this.charts.regional) {
            this.charts.regional.destroy();
        }

        const regions = Object.keys(regionalData);
        const counts = Object.values(regionalData);

        this.charts.regional = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: regions,
                datasets: [{
                    label: 'Resources',
                    data: counts,
                    backgroundColor: '#3b82f6',
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }

    createRiskTrendChart(riskData) {
        const ctx = document.getElementById('riskTrendChart');
        if (!ctx) return;

        if (this.charts.riskTrend) {
            this.charts.riskTrend.destroy();
        }

        this.charts.riskTrend = new Chart(ctx, {
            type: 'line',
            data: {
                labels: riskData.map(d => new Date(d.date).toLocaleDateString()),
                datasets: [{
                    label: 'Risk Score',
                    data: riskData.map(d => d.risk_score),
                    borderColor: '#dc2626',
                    backgroundColor: 'rgba(220, 38, 38, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });
    }

    updateRecentActivities(data) {
        const container = document.getElementById('recentActivities');
        if (!container) return;

        // Mock recent activities based on findings
        const activities = [
            {
                type: 'security_finding',
                title: 'Critical security finding detected',
                time: '2 minutes ago',
                icon: 'fas fa-exclamation-triangle',
                severity: 'critical'
            },
            {
                type: 'remediation',
                title: 'S3 bucket public access blocked',
                time: '15 minutes ago',
                icon: 'fas fa-shield-alt',
                severity: 'success'
            },
            {
                type: 'scan',
                title: 'Security scan completed',
                time: '1 hour ago',
                icon: 'fas fa-search',
                severity: 'info'
            }
        ];

        container.innerHTML = activities.map(activity => `
            <div class="activity-item ${activity.severity}">
                <div class="activity-icon">
                    <i class="${activity.icon}"></i>
                </div>
                <div class="activity-content">
                    <div class="activity-title">${activity.title}</div>
                    <div class="activity-time">${activity.time}</div>
                </div>
            </div>
        `).join('');
    }

    async loadFindings() {
        try {
            this.showLoading();
            
            const response = await fetch('/api/security/findings');
            const data = await response.json();

            if (data.success) {
                this.updateFindingsTable(data.data);
                this.updateFindingsStats(data.data);
            } else {
                this.showNotification('Error loading findings', 'error');
            }
        } catch (error) {
            console.error('Error loading findings:', error);
            this.showNotification('Failed to load findings', 'error');
        } finally {
            this.hideLoading();
        }
    }

    updateFindingsTable(findings) {
        const tbody = document.getElementById('findingsTableBody');
        if (!tbody) return;

        tbody.innerHTML = findings.map(finding => `
            <tr onclick="showFindingDetails('${finding.id}')">
                <td>
                    <span class="severity-badge ${finding.severity}">${finding.severity.toUpperCase()}</span>
                </td>
                <td>${finding.title}</td>
                <td>${finding.resource?.resource_id || 'N/A'}</td>
                <td>${finding.resource?.region || 'N/A'}</td>
                <td>
                    <span class="status-badge ${finding.status}">${finding.status}</span>
                </td>
                <td>${new Date(finding.created_at).toLocaleDateString()}</td>
                <td>
                    <button class="action-btn" onclick="remediateFinding('${finding.id}')">
                        <i class="fas fa-wrench"></i>
                    </button>
                    <button class="action-btn" onclick="suppressFinding('${finding.id}')">
                        <i class="fas fa-eye-slash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    }

    updateFindingsStats(findings) {
        const stats = findings.reduce((acc, finding) => {
            acc[finding.severity] = (acc[finding.severity] || 0) + 1;
            return acc;
        }, {});

        document.getElementById('criticalCount').textContent = stats.critical || 0;
        document.getElementById('highCount').textContent = stats.high || 0;
        document.getElementById('mediumCount').textContent = stats.medium || 0;
        document.getElementById('lowCount').textContent = stats.low || 0;
    }

    async loadComplianceData(framework = 'all') {
        try {
            this.showLoading();
            
            const response = await fetch(`/api/analytics/compliance-report?framework=${framework}`);
            const data = await response.json();

            if (data.success) {
                this.updateComplianceOverview(data.data);
                this.updateComplianceFrameworks(data.data.frameworks);
                this.updateComplianceViolations(data.data.top_violations);
                this.updateRemediationPriorities(data.data.remediation_priorities);
            } else {
                this.showNotification('Error loading compliance data', 'error');
            }
        } catch (error) {
            console.error('Error loading compliance data:', error);
            this.showNotification('Failed to load compliance data', 'error');
        } finally {
            this.hideLoading();
        }
    }

    updateComplianceOverview(data) {
        const summary = data.summary;
        
        document.getElementById('overallComplianceScore').textContent = summary.compliance_score || 0;
        document.getElementById('passedChecks').textContent = summary.passed || 0;
        document.getElementById('failedChecks').textContent = summary.failed || 0;
        document.getElementById('warningChecks').textContent = summary.warnings || 0;

        // Create compliance score chart
        this.createComplianceScoreChart(summary.compliance_score || 0);
    }

    createComplianceScoreChart(score) {
        const ctx = document.getElementById('complianceScoreChart');
        if (!ctx) return;

        if (this.charts.complianceScore) {
            this.charts.complianceScore.destroy();
        }

        this.charts.complianceScore = new Chart(ctx, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [score, 100 - score],
                    backgroundColor: [
                        score >= 80 ? '#10b981' : score >= 60 ? '#f59e0b' : '#ef4444',
                        '#e5e7eb'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }

    updateComplianceFrameworks(frameworks) {
        const container = document.getElementById('frameworksGrid');
        if (!container) return;

        container.innerHTML = Object.entries(frameworks).map(([name, data]) => `
            <div class="framework-card">
                <div class="framework-header">
                    <h4>${name}</h4>
                    <span class="framework-score ${data.compliance_score >= 80 ? 'good' : data.compliance_score >= 60 ? 'warning' : 'poor'}">
                        ${data.compliance_score}%
                    </span>
                </div>
                <div class="framework-stats">
                    <div class="stat">
                        <span class="stat-label">Passed:</span>
                        <span class="stat-value">${data.passed}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Failed:</span>
                        <span class="stat-value">${data.failed}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Warnings:</span>
                        <span class="stat-value">${data.warnings}</span>
                    </div>
                </div>
            </div>
        `).join('');
    }

    updateComplianceViolations(violations) {
        const container = document.getElementById('violationsList');
        if (!container) return;

        container.innerHTML = violations.map(violation => `
            <div class="violation-item">
                <div class="violation-title">${violation.violation}</div>
                <div class="violation-count">${violation.count} occurrences</div>
            </div>
        `).join('');
    }

    updateRemediationPriorities(priorities) {
        const container = document.getElementById('prioritiesList');
        if (!container) return;

        container.innerHTML = priorities.map(priority => `
            <div class="priority-item">
                <div class="priority-header">
                    <span class="priority-level ${priority.priority.toLowerCase()}">${priority.priority}</span>
                    <span class="priority-title">${priority.title}</span>
                </div>
                <div class="priority-details">
                    <span class="priority-impact">Impact: ${priority.impact}</span>
                    <span class="priority-effort">Effort: ${priority.effort}</span>
                </div>
                <div class="priority-recommendation">${priority.recommendation}</div>
            </div>
        `).join('');
    }

    async loadThreatIntelligence(days = 7) {
        try {
            this.showLoading();
            
            const response = await fetch(`/api/analytics/threat-intelligence?days=${days}`);
            const data = await response.json();

            if (data.success) {
                this.updateThreatSummary(data.data);
                this.updateThreatCharts(data.data);
                this.updateThreatTimeline(data.data.recent_activities);
                this.updateThreatRecommendations(data.data.recommendations);
            } else {
                this.showNotification('Error loading threat intelligence', 'error');
            }
        } catch (error) {
            console.error('Error loading threat intelligence:', error);
            this.showNotification('Failed to load threat intelligence', 'error');
        } finally {
            this.hideLoading();
        }
    }

    updateThreatSummary(data) {
        const summary = data.summary;
        
        document.getElementById('totalThreats').textContent = summary.total_threats || 0;
        document.getElementById('highSeverityThreats').textContent = summary.high_severity_threats || 0;
        document.getElementById('activeInvestigations').textContent = summary.active_investigations || 0;
        document.getElementById('resolvedThreats').textContent = summary.resolved_threats || 0;
    }

    updateThreatCharts(data) {
        // Threat Categories Chart
        this.createThreatCategoriesChart(data.threat_categories);
        
        // Geographic Distribution Chart
        this.createGeographicChart(data.geographic_distribution);
        
        // Attack Vectors Chart
        this.createAttackVectorsChart(data.attack_vectors);
    }

    createThreatCategoriesChart(categories) {
        const ctx = document.getElementById('threatCategoriesChart');
        if (!ctx) return;

        if (this.charts.threatCategories) {
            this.charts.threatCategories.destroy();
        }

        const labels = Object.keys(categories);
        const data = Object.values(categories);

        this.charts.threatCategories = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: [
                        '#3b82f6',
                        '#ef4444',
                        '#f59e0b',
                        '#10b981',
                        '#8b5cf6',
                        '#f97316'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }

    createGeographicChart(geographic) {
        const ctx = document.getElementById('geographicChart');
        if (!ctx) return;

        if (this.charts.geographic) {
            this.charts.geographic.destroy();
        }

        const labels = Object.keys(geographic);
        const data = Object.values(geographic);

        this.charts.geographic = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Threats',
                    data: data,
                    backgroundColor: '#ef4444'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }

    createAttackVectorsChart(vectors) {
        const ctx = document.getElementById('attackVectorsChart');
        if (!ctx) return;

        if (this.charts.attackVectors) {
            this.charts.attackVectors.destroy();
        }

        const labels = Object.keys(vectors);
        const data = Object.values(vectors);

        this.charts.attackVectors = new Chart(ctx, {
            type: 'horizontalBar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Count',
                    data: data,
                    backgroundColor: '#8b5cf6'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }

    updateThreatTimeline(activities) {
        const container = document.getElementById('threatsTimeline');
        if (!container) return;

        container.innerHTML = activities.map(activity => `
            <div class="timeline-item">
                <div class="timeline-marker ${activity.severity}"></div>
                <div class="timeline-content">
                    <div class="timeline-header">
                        <span class="timeline-title">${activity.description}</span>
                        <span class="timeline-time">${new Date(activity.timestamp).toLocaleString()}</span>
                    </div>
                    <div class="timeline-details">
                        <span class="timeline-type">${activity.type}</span>
                        <span class="timeline-source">${activity.source}</span>
                    </div>
                </div>
            </div>
        `).join('');
    }

    updateThreatRecommendations(recommendations) {
        const container = document.getElementById('threatRecommendations');
        if (!container) return;

        container.innerHTML = recommendations.map(rec => `
            <div class="recommendation-item">
                <div class="recommendation-header">
                    <span class="recommendation-category">${rec.category}</span>
                    <span class="recommendation-priority ${rec.priority.toLowerCase()}">${rec.priority}</span>
                </div>
                <div class="recommendation-text">${rec.recommendation}</div>
                <div class="recommendation-action">${rec.action}</div>
            </div>
        `).join('');
    }

    async loadResourceInventory() {
        try {
            this.showLoading();
            
            const response = await fetch('/api/analytics/resource-inventory');
            const data = await response.json();

            if (data.success) {
                this.updateResourceSummary(data.data);
                this.updateResourceCharts(data.data);
                this.updateResourcesTable(data.data.recent_changes);
            } else {
                this.showNotification('Error loading resource inventory', 'error');
            }
        } catch (error) {
            console.error('Error loading resource inventory:', error);
            this.showNotification('Failed to load resource inventory', 'error');
        } finally {
            this.hideLoading();
        }
    }

    updateResourceSummary(data) {
        const summary = data.summary;
        
        document.getElementById('totalResourcesCount').textContent = summary.total_resources || 0;
        document.getElementById('resourceTypesCount').textContent = summary.resource_types || 0;
        document.getElementById('regionsCoveredCount').textContent = summary.regions_covered || 0;
        document.getElementById('coveragePercentage').textContent = summary.coverage_percentage || 0;
    }

    updateResourceCharts(data) {
        // Resource Type Chart
        this.createResourceTypeChart(data.distribution.by_type);
        
        // Resource Region Chart
        this.createResourceRegionChart(data.distribution.by_region);
        
        // Resource Risk Chart
        this.createResourceRiskChart(data.risk_analysis.risk_scores_by_type);
    }

    createResourceTypeChart(typeData) {
        const ctx = document.getElementById('resourceTypeChart');
        if (!ctx) return;

        if (this.charts.resourceType) {
            this.charts.resourceType.destroy();
        }

        const labels = Object.keys(typeData);
        const data = Object.values(typeData);

        this.charts.resourceType = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: [
                        '#3b82f6',
                        '#ef4444',
                        '#f59e0b',
                        '#10b981',
                        '#8b5cf6',
                        '#f97316',
                        '#06b6d4',
                        '#84cc16'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }

    createResourceRegionChart(regionData) {
        const ctx = document.getElementById('resourceRegionChart');
        if (!ctx) return;

        if (this.charts.resourceRegion) {
            this.charts.resourceRegion.destroy();
        }

        const labels = Object.keys(regionData);
        const data = Object.values(regionData);

        this.charts.resourceRegion = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Resources',
                    data: data,
                    backgroundColor: '#3b82f6'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }

    createResourceRiskChart(riskData) {
        const ctx = document.getElementById('resourceRiskChart');
        if (!ctx) return;

        if (this.charts.resourceRisk) {
            this.charts.resourceRisk.destroy();
        }

        const labels = Object.keys(riskData);
        const data = Object.values(riskData);

        this.charts.resourceRisk = new Chart(ctx, {
            type: 'radar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Risk Score',
                    data: data,
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });
    }

    updateResourcesTable(resources) {
        const tbody = document.getElementById('resourcesTableBody');
        if (!tbody) return;

        tbody.innerHTML = resources.map(resource => `
            <tr>
                <td>${resource.resource_id}</td>
                <td>${resource.resource_type}</td>
                <td>${resource.region}</td>
                <td>${new Date(resource.created_at).toLocaleDateString()}</td>
                <td>
                    <span class="risk-score ${this.getRiskLevel(50)}">50</span>
                </td>
                <td>
                    <button class="action-btn" onclick="scanResource('${resource.resource_id}')">
                        <i class="fas fa-search"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    }

    async loadAnalyticsData(days = 30) {
        try {
            this.showLoading();
            
            const [trendsResponse, performanceResponse] = await Promise.all([
                fetch(`/api/analytics/security-trends?days=${days}`),
                fetch(`/api/analytics/performance-metrics?days=${days}`)
            ]);

            const trendsData = await trendsResponse.json();
            const performanceData = await performanceResponse.json();

            if (trendsData.success && performanceData.success) {
                this.updateSecurityTrends(trendsData.data);
                this.updatePerformanceMetrics(performanceData.data);
                this.updateSystemHealth(performanceData.data.system_health);
            } else {
                this.showNotification('Error loading analytics data', 'error');
            }
        } catch (error) {
            console.error('Error loading analytics data:', error);
            this.showNotification('Failed to load analytics data', 'error');
        } finally {
            this.hideLoading();
        }
    }

    updateSecurityTrends(data) {
        this.createSecurityTrendsChart(data.finding_trends);
        this.createDetectionEfficiencyChart(data);
        this.createRiskForecastChart(data);
        this.createComplianceTrendsChart(data.compliance_trends);
    }

    createSecurityTrendsChart(trendData) {
        const ctx = document.getElementById('securityTrendsChart');
        if (!ctx) return;

        if (this.charts.securityTrends) {
            this.charts.securityTrends.destroy();
        }

        this.charts.securityTrends = new Chart(ctx, {
            type: 'line',
            data: {
                labels: trendData.map(d => new Date(d.date).toLocaleDateString()),
                datasets: [{
                    label: 'Total Findings',
                    data: trendData.map(d => d.total),
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }

    createDetectionEfficiencyChart(data) {
        const ctx = document.getElementById('detectionEfficiencyChart');
        if (!ctx) return;

        if (this.charts.detectionEfficiency) {
            this.charts.detectionEfficiency.destroy();
        }

        // Mock data for detection efficiency
        this.charts.detectionEfficiency = new Chart(ctx, {
            type: 'gauge',
            data: {
                datasets: [{
                    data: [85],
                    backgroundColor: ['#10b981', '#e5e7eb']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });
    }

    createRiskForecastChart(data) {
        const ctx = document.getElementById('riskForecastChart');
        if (!ctx) return;

        if (this.charts.riskForecast) {
            this.charts.riskForecast.destroy();
        }

        // Mock forecast data
        const forecastData = [65, 62, 58, 55, 52, 48, 45];
        const labels = [];
        for (let i = 0; i < 7; i++) {
            const date = new Date();
            date.setDate(date.getDate() + i);
            labels.push(date.toLocaleDateString());
        }

        this.charts.riskForecast = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Predicted Risk Score',
                    data: forecastData,
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    borderDash: [5, 5],
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }

    createComplianceTrendsChart(complianceData) {
        const ctx = document.getElementById('complianceTrendsChart');
        if (!ctx) return;

        if (this.charts.complianceTrends) {
            this.charts.complianceTrends.destroy();
        }

        this.charts.complianceTrends = new Chart(ctx, {
            type: 'line',
            data: {
                labels: complianceData.map(d => new Date(d.date).toLocaleDateString()),
                datasets: [
                    {
                        label: 'Compliant',
                        data: complianceData.map(d => d.compliant),
                        borderColor: '#10b981',
                        backgroundColor: 'rgba(16, 185, 129, 0.1)'
                    },
                    {
                        label: 'Non-Compliant',
                        data: complianceData.map(d => d.non_compliant),
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }

    updatePerformanceMetrics(data) {
        const container = document.getElementById('performanceMetrics');
        if (!container) return;

        const scanPerf = data.scan_performance;
        const remediationPerf = data.remediation_performance;
        const detectionEff = data.detection_efficiency;

        container.innerHTML = `
            <div class="performance-metric">
                <div class="metric-label">Scan Success Rate</div>
                <div class="metric-value">${scanPerf.success_rate}%</div>
            </div>
            <div class="performance-metric">
                <div class="metric-label">Avg Scan Time</div>
                <div class="metric-value">${scanPerf.average_scan_time}s</div>
            </div>
            <div class="performance-metric">
                <div class="metric-label">Remediation Success</div>
                <div class="metric-value">${remediationPerf.success_rate}%</div>
            </div>
            <div class="performance-metric">
                <div class="metric-label">Detection Efficiency</div>
                <div class="metric-value">${detectionEff.detection_coverage}%</div>
            </div>
        `;
    }

    updateSystemHealth(healthData) {
        const container = document.getElementById('systemHealth');
        if (!container) return;

        container.innerHTML = `
            <div class="health-metric">
                <div class="metric-label">Database Size</div>
                <div class="metric-value">${healthData.database_size}</div>
            </div>
            <div class="health-metric">
                <div class="metric-label">Memory Usage</div>
                <div class="metric-value">${healthData.memory_usage.percentage}%</div>
            </div>
            <div class="health-metric">
                <div class="metric-label">Active Connections</div>
                <div class="metric-value">${healthData.active_connections}</div>
            </div>
            <div class="health-metric">
                <div class="metric-label">Avg Response Time</div>
                <div class="metric-value">${healthData.response_times.dashboard}ms</div>
            </div>
        `;
    }

    // Utility methods
    getRiskLevel(score) {
        if (score >= 80) return 'high';
        if (score >= 60) return 'medium';
        if (score >= 40) return 'low';
        return 'minimal';
    }

    showLoading() {
        document.getElementById('loadingOverlay').style.display = 'flex';
    }

    hideLoading() {
        document.getElementById('loadingOverlay').style.display = 'none';
    }

    showNotification(message, type = 'info') {
        const container = document.getElementById('notificationContainer');
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <span>${message}</span>
                <button class="notification-close" onclick="this.parentElement.parentElement.remove()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        
        container.appendChild(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }

    startAutoRefresh() {
        // Refresh dashboard every 5 minutes
        this.refreshInterval = setInterval(() => {
            if (this.currentTab === 'overview') {
                this.loadDashboardData();
            }
        }, 300000);
    }

    filterFindings() {
        // Implementation for filtering findings
        console.log('Filtering findings...');
    }

    filterResources() {
        // Implementation for filtering resources
        console.log('Filtering resources...');
    }

    updateChartPeriod(period) {
        // Update chart controls
        document.querySelectorAll('.chart-control').forEach(control => {
            control.classList.remove('active');
        });
        document.querySelector(`[data-period="${period}"]`).classList.add('active');
        
        // Reload data for the new period
        const days = period === '7d' ? 7 : period === '30d' ? 30 : 90;
        this.loadDashboardData(days);
    }
}

// Global functions for event handlers
function refreshDashboard() {
    dashboard.loadDashboardData();
}

function startScan() {
    dashboard.showNotification('Security scan started', 'info');
    // Implementation for starting scan
}

function runComplianceScan() {
    dashboard.showNotification('Compliance scan started', 'info');
    // Implementation for compliance scan
}

function analyzeThreatIntelligence() {
    dashboard.showNotification('Analyzing threat intelligence...', 'info');
    // Implementation for threat analysis
}

function discoverResources() {
    dashboard.showNotification('Resource discovery started', 'info');
    // Implementation for resource discovery
}

function exportReport() {
    dashboard.showNotification('Generating report...', 'info');
    // Implementation for report export
}

function showFindingDetails(findingId) {
    // Implementation for showing finding details
    console.log('Showing finding details for:', findingId);
}

function remediateFinding(findingId) {
    dashboard.showNotification('Starting remediation...', 'info');
    // Implementation for remediation
}

function suppressFinding(findingId) {
    dashboard.showNotification('Finding suppressed', 'success');
    // Implementation for suppressing finding
}

function scanResource(resourceId) {
    dashboard.showNotification('Scanning resource...', 'info');
    // Implementation for resource scanning
}

function closeFindingModal() {
    document.getElementById('findingModal').style.display = 'none';
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new SecurityDashboard();
});

