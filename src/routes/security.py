from flask import Blueprint, jsonify, request
from datetime import datetime
import logging
from src.models.security import AWSResource, SecurityFinding, SecurityPolicy, ScanJob, db
from src.services.aws_client import AWSClient
from src.services.security_scanner import SecurityScanner, ComplianceChecker

security_bp = Blueprint('security', __name__)
logger = logging.getLogger(__name__)

# Initialize AWS client and scanner
aws_client = AWSClient()
security_scanner = SecurityScanner(aws_client)
compliance_checker = ComplianceChecker()

@security_bp.route('/aws/test-connection', methods=['GET'])
def test_aws_connection():
    """Test AWS connection and permissions"""
    try:
        connection_result = aws_client.test_connection()
        return jsonify(connection_result)
    except Exception as e:
        logger.error(f"AWS connection test failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@security_bp.route('/scan/start', methods=['POST'])
def start_security_scan():
    """Start a comprehensive security scan"""
    try:
        data = request.get_json() or {}
        regions = data.get('regions', [aws_client.config.AWS_DEFAULT_REGION])
        
        # Create scan job record
        scan_job = ScanJob(
            job_type='security_scan',
            status='running',
            region=','.join(regions),
            started_at=datetime.utcnow()
        )
        db.session.add(scan_job)
        db.session.commit()
        
        # Start the scan
        scan_results = security_scanner.scan_all_resources(regions)
        
        # Update scan job
        scan_job.status = scan_results['status']
        scan_job.completed_at = datetime.utcnow()
        scan_job.resources_scanned = scan_results['resources_scanned']
        scan_job.findings_created = scan_results['findings_created']
        if scan_results.get('error'):
            scan_job.error_message = scan_results['error']
        
        db.session.commit()
        
        return jsonify({
            'scan_job_id': scan_job.id,
            'status': scan_results['status'],
            'resources_scanned': scan_results['resources_scanned'],
            'findings_created': scan_results['findings_created']
        })
        
    except Exception as e:
        logger.error(f"Failed to start security scan: {str(e)}")
        return jsonify({'error': str(e)}), 500

@security_bp.route('/resources', methods=['GET'])
def get_resources():
    """Get all AWS resources"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        resource_type = request.args.get('type')
        region = request.args.get('region')
        
        query = AWSResource.query
        
        if resource_type:
            query = query.filter(AWSResource.resource_type == resource_type)
        if region:
            query = query.filter(AWSResource.region == region)
        
        resources = query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'resources': [resource.to_dict() for resource in resources.items],
            'total': resources.total,
            'pages': resources.pages,
            'current_page': page,
            'per_page': per_page
        })
        
    except Exception as e:
        logger.error(f"Failed to get resources: {str(e)}")
        return jsonify({'error': str(e)}), 500

@security_bp.route('/resources/<int:resource_id>', methods=['GET'])
def get_resource(resource_id):
    """Get specific AWS resource"""
    try:
        resource = AWSResource.query.get_or_404(resource_id)
        return jsonify(resource.to_dict())
    except Exception as e:
        logger.error(f"Failed to get resource {resource_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@security_bp.route('/findings', methods=['GET'])
def get_findings():
    """Get security findings"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        severity = request.args.get('severity')
        status = request.args.get('status', 'open')
        finding_type = request.args.get('type')
        
        query = SecurityFinding.query
        
        if severity:
            query = query.filter(SecurityFinding.severity == severity)
        if status:
            query = query.filter(SecurityFinding.status == status)
        if finding_type:
            query = query.filter(SecurityFinding.finding_type == finding_type)
        
        # Order by severity and creation date
        severity_order = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'info': 5}
        findings = query.order_by(
            db.case(severity_order, value=SecurityFinding.severity),
            SecurityFinding.created_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'findings': [finding.to_dict() for finding in findings.items],
            'total': findings.total,
            'pages': findings.pages,
            'current_page': page,
            'per_page': per_page
        })
        
    except Exception as e:
        logger.error(f"Failed to get findings: {str(e)}")
        return jsonify({'error': str(e)}), 500

@security_bp.route('/findings/<int:finding_id>', methods=['GET'])
def get_finding(finding_id):
    """Get specific security finding"""
    try:
        finding = SecurityFinding.query.get_or_404(finding_id)
        return jsonify(finding.to_dict())
    except Exception as e:
        logger.error(f"Failed to get finding {finding_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@security_bp.route('/findings/<int:finding_id>/resolve', methods=['POST'])
def resolve_finding(finding_id):
    """Mark a finding as resolved"""
    try:
        finding = SecurityFinding.query.get_or_404(finding_id)
        finding.status = 'resolved'
        finding.resolved_at = datetime.utcnow()
        finding.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'message': 'Finding resolved successfully',
            'finding': finding.to_dict()
        })
        
    except Exception as e:
        logger.error(f"Failed to resolve finding {finding_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@security_bp.route('/findings/<int:finding_id>/suppress', methods=['POST'])
def suppress_finding(finding_id):
    """Suppress a finding"""
    try:
        finding = SecurityFinding.query.get_or_404(finding_id)
        finding.status = 'suppressed'
        finding.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'message': 'Finding suppressed successfully',
            'finding': finding.to_dict()
        })
        
    except Exception as e:
        logger.error(f"Failed to suppress finding {finding_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@security_bp.route('/dashboard/summary', methods=['GET'])
def get_dashboard_summary():
    """Get security dashboard summary"""
    try:
        # Get resource counts
        total_resources = AWSResource.query.count()
        resources_by_type = db.session.query(
            AWSResource.resource_type,
            db.func.count(AWSResource.id)
        ).group_by(AWSResource.resource_type).all()
        
        # Get finding counts
        total_findings = SecurityFinding.query.filter_by(status='open').count()
        findings_by_severity = db.session.query(
            SecurityFinding.severity,
            db.func.count(SecurityFinding.id)
        ).filter_by(status='open').group_by(SecurityFinding.severity).all()
        
        # Get recent scan jobs
        recent_scans = ScanJob.query.order_by(
            ScanJob.created_at.desc()
        ).limit(5).all()
        
        # Calculate security score (simplified)
        critical_findings = SecurityFinding.query.filter_by(
            severity='critical', status='open'
        ).count()
        high_findings = SecurityFinding.query.filter_by(
            severity='high', status='open'
        ).count()
        
        # Simple scoring: 100 - (critical * 10 + high * 5)
        security_score = max(0, 100 - (critical_findings * 10 + high_findings * 5))
        
        return jsonify({
            'summary': {
                'total_resources': total_resources,
                'total_findings': total_findings,
                'security_score': security_score,
                'last_scan': recent_scans[0].to_dict() if recent_scans else None
            },
            'resources_by_type': dict(resources_by_type),
            'findings_by_severity': dict(findings_by_severity),
            'recent_scans': [scan.to_dict() for scan in recent_scans]
        })
        
    except Exception as e:
        logger.error(f"Failed to get dashboard summary: {str(e)}")
        return jsonify({'error': str(e)}), 500

@security_bp.route('/compliance/cis', methods=['GET'])
def get_cis_compliance():
    """Get CIS compliance report"""
    try:
        compliance_report = compliance_checker.check_cis_compliance()
        return jsonify(compliance_report)
    except Exception as e:
        logger.error(f"Failed to get CIS compliance: {str(e)}")
        return jsonify({'error': str(e)}), 500

@security_bp.route('/scan-jobs', methods=['GET'])
def get_scan_jobs():
    """Get scan job history"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        scan_jobs = ScanJob.query.order_by(
            ScanJob.created_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'scan_jobs': [job.to_dict() for job in scan_jobs.items],
            'total': scan_jobs.total,
            'pages': scan_jobs.pages,
            'current_page': page,
            'per_page': per_page
        })
        
    except Exception as e:
        logger.error(f"Failed to get scan jobs: {str(e)}")
        return jsonify({'error': str(e)}), 500

@security_bp.route('/regions', methods=['GET'])
def get_aws_regions():
    """Get available AWS regions"""
    try:
        regions = aws_client.get_available_regions()
        return jsonify({'regions': regions})
    except Exception as e:
        logger.error(f"Failed to get AWS regions: {str(e)}")
        return jsonify({'error': str(e)}), 500

@security_bp.route('/resource-types', methods=['GET'])
def get_resource_types():
    """Get supported AWS resource types"""
    try:
        from src.config import AWS_RESOURCE_TYPES
        return jsonify({'resource_types': AWS_RESOURCE_TYPES})
    except Exception as e:
        logger.error(f"Failed to get resource types: {str(e)}")
        return jsonify({'error': str(e)}), 500

@security_bp.route('/findings/stats', methods=['GET'])
def get_findings_stats():
    """Get findings statistics"""
    try:
        # Get findings by severity
        severity_stats = db.session.query(
            SecurityFinding.severity,
            db.func.count(SecurityFinding.id)
        ).filter_by(status='open').group_by(SecurityFinding.severity).all()
        
        # Get findings by type
        type_stats = db.session.query(
            SecurityFinding.finding_type,
            db.func.count(SecurityFinding.id)
        ).filter_by(status='open').group_by(SecurityFinding.finding_type).all()
        
        # Get findings trend (last 30 days)
        from datetime import datetime, timedelta
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        trend_stats = db.session.query(
            db.func.date(SecurityFinding.created_at).label('date'),
            db.func.count(SecurityFinding.id).label('count')
        ).filter(
            SecurityFinding.created_at >= thirty_days_ago
        ).group_by(
            db.func.date(SecurityFinding.created_at)
        ).order_by('date').all()
        
        return jsonify({
            'by_severity': dict(severity_stats),
            'by_type': dict(type_stats),
            'trend': [{'date': str(item.date), 'count': item.count} for item in trend_stats]
        })
        
    except Exception as e:
        logger.error(f"Failed to get findings stats: {str(e)}")
        return jsonify({'error': str(e)}), 500

