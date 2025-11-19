from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import random
import uuid
from datetime import datetime, timedelta

app = FastAPI(
    title="Spectraine API",
    description="Cloud Threat Detection & Cost Optimization",
    version="2.0.0"
)

# FIXED CORS CONFIGURATION - MUST BE BEFORE ROUTES
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

# Data Models
class InstanceResponse(BaseModel):
    id: str
    name: str
    state: str
    instance_type: str
    public_ip: Optional[str]
    private_ip: Optional[str]
    launch_time: str
    threats: List[str]
    monthly_cost: float
    region: str

class ThreatFinding(BaseModel):
    type: str
    severity: str
    instance: str
    instance_name: str
    impact: str
    confidence: str
    business_impact: str
    recommendation: str

class CostRecommendation(BaseModel):
    recommendation: str
    potential_savings: str
    confidence: str
    business_translation: str
    implementation_effort: str

class AssessmentRequest(BaseModel):
    name: str
    email: str
    company: str
    aws_spend: Optional[str] = "unknown"
    priority_concerns: List[str] = []

class QuickScanResponse(BaseModel):
    status: str
    scan_time: str
    critical_findings: int
    immediate_risks: List[Dict[str, Any]]
    next_actions: List[str]

# Enhanced Mock Data Generators
def generate_instances():
    """Generate realistic demo instances for enterprise environment"""
    instance_templates = [
        {"type": "t3.large", "cost": 67.20, "typical_use": "web server", "threat_weight": 0.3},
        {"type": "r5.xlarge", "cost": 252.00, "typical_use": "database", "threat_weight": 0.6},
        {"type": "m5.2xlarge", "cost": 384.00, "typical_use": "application server", "threat_weight": 0.4},
        {"type": "c5.4xlarge", "cost": 680.00, "typical_use": "compute intensive", "threat_weight": 0.7},
        {"type": "t2.micro", "cost": 9.50, "typical_use": "development", "threat_weight": 0.2},
        {"type": "g4dn.xlarge", "cost": 526.00, "typical_use": "gpu workload", "threat_weight": 0.8},
        {"type": "i3.2xlarge", "cost": 624.00, "typical_use": "storage optimized", "threat_weight": 0.5},
        {"type": "r5d.2xlarge", "cost": 576.00, "typical_use": "memory intensive", "threat_weight": 0.6}
    ]
    
    regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ap-northeast-1"]
    environments = ["prod", "staging", "dev", "qa", "uat"]
    
    instances = []
    num_instances = random.randint(12, 18)
    
    for i in range(num_instances):
        template = random.choice(instance_templates)
        region = random.choice(regions)
        env = random.choice(environments)
        role = template["typical_use"].replace(" ", "-")
        
        # Create realistic instance names
        name_parts = [
            f"{env}",
            f"{role}",
            f"{region}",
            f"{random.choice(['api', 'service', 'app', 'backend', 'frontend'])}",
            f"{i+1:02d}"
        ]
        random.shuffle(name_parts)
        instance_name = "-".join(name_parts)
        
        instances.append({
            "id": f"i-{random.randint(100000000, 999999999)}",
            "name": instance_name,
            "state": random.choice(["running", "stopped", "running", "running", "running"]),
            "instance_type": template["type"],
            "public_ip": f"{random.randint(50,60)}.{random.randint(200,250)}.{random.randint(1,255)}.{random.randint(1,255)}" if random.random() > 0.4 else None,
            "private_ip": f"10.{random.randint(0,5)}.{random.randint(1,255)}.{random.randint(10,250)}",
            "launch_time": (datetime.now() - timedelta(days=random.randint(1, 365))).isoformat(),
            "threats": generate_instance_threats(template),
            "monthly_cost": template["cost"] * random.uniform(0.8, 1.2),
            "region": region
        })
    
    return instances

def generate_instance_threats(template):
    """Generate realistic threats based on instance type and characteristics"""
    threats = []
    
    # High-cost instances are often overprovisioned
    if template["cost"] > 300 and random.random() > 0.3:
        threats.append("overprovisioned")
    
    # GPU instances often used for cryptomining
    if template["type"].startswith("g") and random.random() > 0.4:
        threats.append("cryptomining")
    
    # Databases often have compliance issues
    if template["typical_use"] == "database" and random.random() > 0.5:
        threats.append("compliance_violation")
        threats.append("data_exposure_risk")
    
    # Development instances often have security issues
    if template["typical_use"] == "development" and random.random() > 0.6:
        threats.append("unencrypted_volumes")
        threats.append("insecure_configuration")
    
    # Storage optimized instances might have data risks
    if template["typical_use"] == "storage optimized" and random.random() > 0.5:
        threats.append("data_retention_violation")
    
    # Add some random critical threats
    if random.random() > 0.7:
        threats.append("data_exfiltration_patterns")
    
    # Ensure at least some instances have threats for demo impact
    if not threats and random.random() > 0.5:
        threats.append("overprovisioned")
    
    return threats

def generate_threats(instances):
    """Generate more detailed and realistic threat findings"""
    threats = []
    
    for instance in instances:
        if "cryptomining" in instance["threats"]:
            cost_impact = instance["monthly_cost"] * random.uniform(1.5, 3.0)
            threats.append({
                "type": "CRYPTOMINING_OPERATION",
                "severity": "CRITICAL",
                "instance": instance["id"],
                "instance_name": instance["name"],
                "impact": f"${cost_impact:,.2f}/month unauthorized compute",
                "confidence": f"{random.randint(92, 99)}%",
                "business_impact": "Infrastructure abuse + security breach + potential legal liability",
                "recommendation": "Immediate termination + security audit + incident response"
            })
        
        if "overprovisioned" in instance["threats"]:
            savings = instance["monthly_cost"] * random.uniform(0.4, 0.7)
            threats.append({
                "type": "RESOURCE_OVERPROVISIONING",
                "severity": "HIGH", 
                "instance": instance["id"],
                "instance_name": instance["name"],
                "impact": f"${savings:,.2f}/month wasted spend",
                "confidence": f"{random.randint(85, 95)}%",
                "business_impact": f"Annual waste: ${savings * 12:,.0f} = 1-2 engineering salaries",
                "recommendation": f"Right-size to {get_smaller_instance(instance['instance_type'])} + implement auto-scaling"
            })
            
        if "compliance_violation" in instance["threats"]:
            threats.append({
                "type": "COMPLIANCE_VIOLATION",
                "severity": "HIGH",
                "instance": instance["id"],
                "instance_name": instance["name"],
                "impact": f"Potential ${random.randint(500000, 2000000):,} HIPAA/GDPR fines",
                "confidence": f"{random.randint(88, 97)}%",
                "business_impact": "Regulatory risk that could halt business operations + customer trust erosion",
                "recommendation": "Immediate compliance remediation + policy enforcement + audit preparation"
            })
            
        if "data_exfiltration_patterns" in instance["threats"]:
            threats.append({
                "type": "DATA_EXFILTRATION",
                "severity": "CRITICAL",
                "instance": instance["id"], 
                "instance_name": instance["name"],
                "impact": f"Potential ${random.randint(2000000, 5000000):,} breach (industry average)",
                "confidence": f"{random.randint(82, 94)}%",
                "business_impact": "Customer data at risk + brand reputation damage + regulatory fines + customer churn",
                "recommendation": "Network segmentation + data loss prevention + enhanced monitoring + incident response"
            })
            
        if "unencrypted_volumes" in instance["threats"]:
            threats.append({
                "type": "UNENCRYPTED_STORAGE",
                "severity": "HIGH",
                "instance": instance["id"],
                "instance_name": instance["name"], 
                "impact": "Data exposure risk + compliance violation",
                "confidence": f"{random.randint(90, 98)}%",
                "business_impact": "Sensitive data vulnerable to theft or unauthorized access + regulatory penalties",
                "recommendation": "Enable EBS encryption + implement encryption policies + data classification"
            })
            
        if "insecure_configuration" in instance["threats"]:
            threats.append({
                "type": "INSECURE_CONFIGURATION",
                "severity": "MEDIUM",
                "instance": instance["id"],
                "instance_name": instance["name"],
                "impact": "Security vulnerability + potential breach vector",
                "confidence": f"{random.randint(80, 92)}%",
                "business_impact": "Increased attack surface + potential security incident",
                "recommendation": "Security hardening + configuration management + compliance scanning"
            })
    
    # Add infrastructure-level threats
    running_instances = [i for i in instances if i['state'] == 'running']
    if len(running_instances) > 10:
        threats.append({
            "type": "INFRASTRUCTURE_WEAKNESS",
            "severity": "HIGH", 
            "instance": "Multiple",
            "instance_name": "Network Architecture",
            "impact": "Distributed attack vulnerability",
            "confidence": f"{random.randint(80, 92)}%",
            "business_impact": "Increased risk of coordinated security incidents + operational disruption",
            "recommendation": "Network segmentation + zero-trust architecture + enhanced monitoring"
        })
    
    # Add compliance framework threats
    if random.random() > 0.3:
        threats.append({
            "type": "COMPLIANCE_FRAMEWORK_GAP",
            "severity": "HIGH",
            "instance": "Organization",
            "instance_name": "Security Program",
            "impact": "Multiple regulatory framework violations",
            "confidence": f"{random.randint(85, 95)}%",
            "business_impact": "Failed audits + customer contract violations + business development limitations",
            "recommendation": "Compliance program development + control implementation + continuous monitoring"
        })
    
    return threats

def get_smaller_instance(current_type):
    """Suggest a smaller instance type"""
    downsizing_map = {
        "r5.xlarge": "r5.large",
        "m5.2xlarge": "m5.xlarge", 
        "c5.4xlarge": "c5.2xlarge",
        "t3.large": "t3.medium",
        "g4dn.xlarge": "g4dn.2xlarge",
        "i3.2xlarge": "i3.xlarge",
        "r5d.2xlarge": "r5d.xlarge"
    }
    return downsizing_map.get(current_type, current_type.replace("xlarge", "large"))

def generate_cost_recommendations(instances):
    """Generate realistic cost optimization recommendations"""
    total_monthly = sum(i["monthly_cost"] for i in instances)
    savings_rate = random.uniform(0.25, 0.45)
    potential_savings = total_monthly * savings_rate
    
    overprovisioned_count = len([i for i in instances if "overprovisioned" in i["threats"]])
    running_instances = [i for i in instances if i["state"] == "running"]
    development_instances = [i for i in instances if "dev" in i["name"] and i["state"] == "running"]
    
    return [
        {
            "recommendation": f"Right-size {overprovisioned_count} overprovisioned instances",
            "potential_savings": f"${potential_savings * 0.6:,.2f}/month",
            "confidence": "High",
            "business_translation": f"Annual savings: ${potential_savings * 0.6 * 12:,.0f} = additional team member budget",
            "implementation_effort": "Low (configuration changes)"
        },
        {
            "recommendation": f"Implement Spot Instances for {len(development_instances)} development workloads",
            "potential_savings": f"${potential_savings * 0.3:,.2f}/month", 
            "confidence": "Medium",
            "business_translation": "70% cost reduction for non-production environments",
            "implementation_effort": "Medium (architecture review)"
        },
        {
            "recommendation": f"Purchase Reserved Instances for {len(running_instances)//3} production workloads",
            "potential_savings": f"${potential_savings * 0.4:,.2f}/month",
            "confidence": "High", 
            "business_translation": "40% savings on stable production infrastructure",
            "implementation_effort": "Low (purchasing only)"
        },
        {
            "recommendation": "Clean up unused EBS volumes and snapshots",
            "potential_savings": f"${potential_savings * 0.15:,.2f}/month",
            "confidence": "High",
            "business_translation": "Eliminate storage waste without impact to operations", 
            "implementation_effort": "Low (automated cleanup)"
        },
        {
            "recommendation": "Optimize data transfer costs between regions",
            "potential_savings": f"${potential_savings * 0.1:,.2f}/month",
            "confidence": "Medium",
            "business_translation": "Reduce unnecessary cross-region data movement",
            "implementation_effort": "Medium (architecture optimization)"
        }
    ]

# API Routes
@app.get("/")
async def root():
    return {
        "message": "Spectraine API - Cloud Threat Detection", 
        "status": "running",
        "version": "2.0.0",
        "demo_mode": True,
        "endpoints": {
            "/": "API information",
            "/health": "Health check",
            "/instances": "Get EC2 instances with threats",
            "/threat-scan": "Run threat detection scan",
            "/cost-analysis": "Get cost optimization recommendations",
            "/free-assessment": "Submit assessment request",
            "/dashboard-metrics": "Get real-time dashboard metrics",
            "/quick-scan": "Run instant threat scan",
            "/simulate-fix": "Simulate fixing all issues",
            "/executive-summary": "Get executive summary report"
        }
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy", 
        "timestamp": datetime.now().isoformat(),
        "service": "Spectraine API",
        "version": "2.0.0",
        "demo_mode": True
    }

@app.get("/instances", response_model=List[InstanceResponse])
async def get_instances():
    """Get all EC2 instances with threat analysis"""
    return generate_instances()

@app.get("/threat-scan")
async def threat_scan():
    """Run comprehensive threat detection scan"""
    instances = generate_instances()
    threats = generate_threats(instances)
    
    critical_threats = len([t for t in threats if t["severity"] == "CRITICAL"])
    high_threats = len([t for t in threats if t["severity"] == "HIGH"])
    
    # Calculate total risk impact
    total_risk = 0
    for threat in threats:
        if "$" in threat["impact"]:
            try:
                amount_str = threat["impact"].split("$")[1].split("/")[0].replace(",", "").replace(" ", "")
                if "M" in amount_str:
                    amount = float(amount_str.replace("M", "")) * 1000000
                else:
                    amount = float(amount_str)
                total_risk += amount
            except:
                continue
    
    return {
        "scan_id": f"scan-{uuid.uuid4().hex[:8]}",
        "threats_found": len(threats),
        "critical_threats": critical_threats,
        "high_threats": high_threats,
        "total_risk": f"${total_risk:,.2f}",
        "details": threats,
        "scan_time": f"{random.randint(45, 120)} seconds",
        "instances_scanned": len(instances),
        "timestamp": datetime.now().isoformat(),
        "risk_level": "CRITICAL" if critical_threats > 0 else "HIGH" if high_threats > 0 else "MEDIUM"
    }

@app.get("/cost-analysis")
async def cost_analysis():
    """Get enhanced cost optimization analysis"""
    instances = generate_instances()
    total_monthly = sum(i["monthly_cost"] for i in instances)
    
    # More realistic savings calculation
    savings_rate = random.uniform(0.25, 0.45)  # 25-45% savings
    savings = total_monthly * savings_rate
    
    # Calculate team member equivalent (avg $100k/year = $8,333/month)
    team_members = savings / 8333
    
    return {
        "analysis_id": f"cost-{uuid.uuid4().hex[:8]}",
        "total_monthly_spend": f"${total_monthly:,.2f}",
        "estimated_annual_spend": f"${total_monthly * 12:,.2f}",
        "potential_savings": f"${savings:,.2f}/month",
        "annual_impact": f"${savings * 12:,.2f}",
        "savings_percentage": f"{savings_rate * 100:.1f}%",
        "recommendations": generate_cost_recommendations(instances),
        "business_impact": f"Savings could fund {team_members:.1f} additional team members",
        "payback_period": f"{random.randint(1, 3)} months",
        "roi": f"{random.randint(400, 1200)}%",
        "scan_date": datetime.now().isoformat()
    }

@app.post("/free-assessment")
async def free_assessment(request: AssessmentRequest):
    """Submit request for free threat assessment"""
    print(f"NEW ASSESSMENT REQUEST:")
    print(f"   Name: {request.name}")
    print(f"   Company: {request.company}")
    print(f"   Email: {request.email}")
    print(f"   AWS Spend: {request.aws_spend}")
    print(f"   Priority Concerns: {request.priority_concerns}")
    print(f"   Timestamp: {datetime.now().isoformat()}")
    
    # Simulate processing
    assessment_id = f"assessment-{uuid.uuid4().hex[:8]}"
    
    return {
        "message": "Assessment scheduled! We'll contact you within 24 hours.",
        "assessment_id": assessment_id,
        "next_steps": [
            "1. Initial environment analysis (2-4 hours)",
            "2. Executive briefing session (30 minutes)",
            "3. Detailed remediation proposal",
            "4. Implementation planning"
        ],
        "demo_findings": "Based on similar companies, we typically find 25-45% cost savings + critical security threats",
        "contact_email": request.email,
        "schedule_confirmation": True,
        "response_time": "24 hours",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/simulate-fix")
async def simulate_fix():
    """Simulate fixing all identified issues"""
    instances = generate_instances()
    total_monthly = sum(i["monthly_cost"] for i in instances)
    savings = total_monthly * random.uniform(0.25, 0.45)
    
    return {
        "message": "All threats remediated and costs optimized!",
        "remediation_id": f"remediation-{uuid.uuid4().hex[:8]}",
        "threats_resolved": random.randint(8, 15),
        "monthly_savings": f"${savings:,.2f}",
        "annual_savings": f"${savings * 12:,.2f}",
        "compliance_achieved": True,
        "security_score_improvement": f"+{random.randint(35, 75)}%",
        "time_to_fix": f"{random.randint(2, 7)} days",
        "roi": f"{random.randint(450, 1200)}%",
        "next_steps": [
            "Continuous monitoring enabled",
            "Compliance reporting automated",
            "Cost optimization ongoing",
            "Security training scheduled"
        ],
        "timestamp": datetime.now().isoformat()
    }

@app.get("/executive-summary")
async def executive_summary():
    """Generate executive summary report"""
    instances = generate_instances()
    threats = generate_threats(instances)
    total_monthly = sum(i["monthly_cost"] for i in instances)
    savings = total_monthly * random.uniform(0.25, 0.45)
    
    critical_threats = len([t for t in threats if t["severity"] == "CRITICAL"])
    high_threats = len([t for t in threats if t["severity"] == "HIGH"])
    
    return {
        "report_id": f"exec-summary-{uuid.uuid4().hex[:8]}",
        "generated_date": datetime.now().isoformat(),
        "executive_overview": {
            "total_instances": len(instances),
            "security_rating": f"{random.randint(45, 75)}/100",
            "cost_efficiency": f"{random.randint(55, 80)}/100",
            "compliance_status": "At Risk",
            "overall_health": "Needs Immediate Attention",
            "business_risk": "High"
        },
        "key_findings": {
            "critical_threats": critical_threats,
            "high_risks": high_threats,
            "total_threats": len(threats),
            "monthly_waste": f"${savings:,.2f}",
            "compliance_gaps": random.randint(2, 6),
            "data_risks": random.randint(3, 8)
        },
        "recommended_actions": [
            "Immediate: Address critical security threats (1-2 days)",
            "Short-term: Optimize overprovisioned resources (3-5 days)", 
            "Strategic: Implement cost governance framework (2 weeks)",
            "Compliance: Remediate regulatory violations (1 week)",
            "Ongoing: Continuous security monitoring (immediate)"
        ],
        "business_impact": {
            "financial_risk": f"${random.randint(500000, 2000000):,}",
            "reputation_risk": "High",
            "operational_risk": "Medium-High",
            "compliance_risk": "High",
            "customer_trust_risk": "High"
        },
        "investment_analysis": {
            "estimated_remediation_cost": "$50,000",
            "potential_annual_savings": f"${savings * 12:,.2f}",
            "risk_reduction": "85-95%",
            "payback_period": f"{random.randint(1, 3)} months",
            "roi": f"{random.randint(400, 1200)}%"
        }
    }

@app.get("/dashboard-metrics")
async def dashboard_metrics():
    """Get real-time dashboard metrics"""
    instances = generate_instances()
    threats = generate_threats(instances)
    total_monthly = sum(i["monthly_cost"] for i in instances)
    
    critical_threats = len([t for t in threats if t["severity"] == "CRITICAL"])
    high_threats = len([t for t in threats if t["severity"] == "HIGH"])
    
    return {
        "total_instances": len(instances),
        "running_instances": len([i for i in instances if i["state"] == "running"]),
        "critical_threats": critical_threats,
        "high_threats": high_threats,
        "total_threats": len(threats),
        "monthly_spend": f"${total_monthly:,.2f}",
        "potential_savings": f"${total_monthly * 0.35:,.2f}",
        "compliance_score": f"{random.randint(65, 85)}%",
        "security_rating": f"{random.randint(4, 7)}/10",
        "cost_efficiency": f"{random.randint(55, 80)}%",
        "last_scan": datetime.now().isoformat(),
        "overall_risk": "HIGH" if critical_threats > 0 else "MEDIUM"
    }

@app.get("/quick-scan", response_model=QuickScanResponse)
async def quick_scan():
    """Fast scan for instant demo impact"""
    instances = generate_instances()
    threats = generate_threats(instances)
    
    critical_threats = [t for t in threats if t["severity"] == "CRITICAL"]
    high_threats = [t for t in threats if t["severity"] == "HIGH"]
    
    immediate_risks = (critical_threats + high_threats)[:3]  # Top 3 risks
    
    return {
        "status": "completed",
        "scan_time": f"{random.randint(15, 60)} seconds",
        "critical_findings": len(critical_threats),
        "immediate_risks": immediate_risks,
        "next_actions": [
            "Immediately terminate cryptomining instances",
            "Begin right-sizing overprovisioned resources", 
            "Schedule emergency security review",
            "Initiate compliance remediation"
        ]
    }

# Required for Render deployment
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)