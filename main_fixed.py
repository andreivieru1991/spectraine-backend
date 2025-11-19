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

# FIXED CORS SETTINGS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)
import React, { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [instances, setInstances] = useState([]);
  const [threats, setThreats] = useState([]);
  const [costAnalysis, setCostAnalysis] = useState(null);
  const [executiveSummary, setExecutiveSummary] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [assessmentForm, setAssessmentForm] = useState({
    name: '',
    email: '',
    company: '',
    aws_spend: ''
  });

  const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  const fetchInstances = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/instances`, {
        headers: {
          'Authorization': 'Bearer demo-token'
        }
      });
      const data = await response.json();
      setInstances(data);
    } catch (error) {
      console.error('Error fetching instances:', error);
    }
    setLoading(false);
  };

  const runThreatScan = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/threat-scan`, {
        headers: {
          'Authorization': 'Bearer demo-token'
        }
      });
      const data = await response.json();
      setThreats(data);
    } catch (error) {
      console.error('Error running threat scan:', error);
    }
    setLoading(false);
  };

  const fetchCostAnalysis = async () => {
    try {
      const response = await fetch(`${API_BASE}/cost-analysis`, {
        headers: {
          'Authorization': 'Bearer demo-token'
        }
      });
      const data = await response.json();
      setCostAnalysis(data);
    } catch (error) {
      console.error('Error fetching cost analysis:', error);
    }
  };

  const fetchExecutiveSummary = async () => {
    try {
      const response = await fetch(`${API_BASE}/executive-summary`, {
        headers: {
          'Authorization': 'Bearer demo-token'
        }
      });
      const data = await response.json();
      setExecutiveSummary(data);
    } catch (error) {
      console.error('Error fetching executive summary:', error);
    }
  };

  const simulateFix = async () => {
    try {
      const response = await fetch(`${API_BASE}/simulate-fix`, {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer demo-token',
          'Content-Type': 'application/json'
        }
      });
      const data = await response.json();
      alert(`✅ ${data.message}\nMonthly Savings: ${data.monthly_savings}\nROI: ${data.roi}`);
    } catch (error) {
      console.error('Error simulating fix:', error);
    }
  };

  const submitAssessment = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch(`${API_BASE}/free-assessment`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer demo-token'
        },
        body: JSON.stringify(assessmentForm)
      });
      const data = await response.json();
      alert('✅ ' + data.message);
      setAssessmentForm({ name: '', email: '', company: '', aws_spend: '' });
    } catch (error) {
      console.error('Error submitting assessment:', error);
    }
  };

  useEffect(() => {
    fetchInstances();
    fetchCostAnalysis();
  }, []);

  const severityColors = {
    CRITICAL: '#ff4444',
    HIGH: '#ff6b35',
    MEDIUM: '#ffa726',
    LOW: '#4caf50'
  };

  return (
    <div className="App">
      {/* Demo Banner */}
      <div className="demo-banner">
        <div className="demo-content">
          <span className="demo-badge">🚀 LIVE DEMO</span>
          <span className="demo-text">
            Spectraine Zero-Cost Demo - No AWS Account Required
          </span>
        </div>
      </div>

      {/* Header */}
      <header className="app-header">
        <div className="header-content">
          <h1>🔍 Spectraine</h1>
          <p>Cloud Threat Detection & Cost Optimization</p>
          <p className="subtitle">Seeing What Others Can't See</p>
        </div>
      </header>

      {/* Navigation */}
      <nav className="app-nav">
        <button 
          className={activeTab === 'dashboard' ? 'nav-btn active' : 'nav-btn'}
          onClick={() => setActiveTab('dashboard')}
        >
          📊 Dashboard
        </button>
        <button 
          className={activeTab === 'threats' ? 'nav-btn active' : 'nav-btn'}
          onClick={() => { setActiveTab('threats'); runThreatScan(); }}
        >
          🚨 Threat Scan
        </button>
        <button 
          className={activeTab === 'costs' ? 'nav-btn active' : 'nav-btn'}
          onClick={() => { setActiveTab('costs'); fetchCostAnalysis(); }}
        >
          💰 Cost Analysis
        </button>
        <button 
          className={activeTab === 'executive' ? 'nav-btn active' : 'nav-btn'}
          onClick={() => { setActiveTab('executive'); fetchExecutiveSummary(); }}
        >
          📈 Executive View
        </button>
        <button 
          className={activeTab === 'assessment' ? 'nav-btn active' : 'nav-btn'}
          onClick={() => setActiveTab('assessment')}
        >
          🔒 Free Assessment
        </button>
      </nav>

      {/* Main Content */}
      <div className="container">
        {activeTab === 'dashboard' && (
          <div className="dashboard">
            <div className="stats-grid">
              <div className="stat-card">
                <h3>EC2 Instances</h3>
                <div className="stat-value">{instances.length}</div>
                <div className="stat-label">Active Resources</div>
              </div>
              <div className="stat-card">
                <h3>Monthly Spend</h3>
                <div className="stat-value">
                  ${instances.reduce((sum, i) => sum + i.monthly_cost, 0).toFixed(2)}
                </div>
                <div className="stat-label">Estimated</div>
              </div>
              <div className="stat-card">
                <h3>Security Threats</h3>
                <div className="stat-value">
                  {instances.reduce((sum, i) => sum + i.threats.length, 0)}
                </div>
                <div className="stat-label">Identified</div>
              </div>
              <div className="stat-card">
                <h3>Potential Savings</h3>
                <div className="stat-value">
                  ${(instances.reduce((sum, i) => sum + i.monthly_cost, 0) * 0.35).toFixed(2)}
                </div>
                <div className="stat-label">Per Month</div>
              </div>
            </div>

            <div className="instances-section">
              <h2>🖥️ EC2 Instances</h2>
              <button onClick={fetchInstances} disabled={loading} className="refresh-btn">
                {loading ? '🔄 Refreshing...' : '🔄 Refresh'}
              </button>
              
              <div className="instances-grid">
                {instances.map(instance => (
                  <div key={instance.id} className="instance-card">
                    <div className="instance-header">
                      <h3>{instance.name}</h3>
                      <span className={`status ${instance.state}`}>
                        {instance.state}
                      </span>
                    </div>
                    
                    <div className="instance-details">
                      <p><strong>ID:</strong> {instance.id}</p>
                      <p><strong>Type:</strong> {instance.instance_type}</p>
                      <p><strong>Cost:</strong> ${instance.monthly_cost}/month</p>
                      <p><strong>Public IP:</strong> {instance.public_ip || 'N/A'}</p>
                    </div>

                    {instance.threats.length > 0 && (
                      <div className="instance-threats">
                        <strong>Threats:</strong>
                        <div className="threat-tags">
                          {instance.threats.map((threat, idx) => (
                            <span key={idx} className="threat-tag">{threat}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'threats' && (
          <div className="threats-tab">
            <div className="tab-header">
              <h2>🚨 Threat Detection Results</h2>
              <button onClick={runThreatScan} disabled={loading} className="scan-btn">
                {loading ? '🔄 Scanning...' : '🔍 Run New Scan'}
              </button>
            </div>

            {threats.details && (
              <div className="threats-results">
                <div className="scan-summary">
                  <h3>Scan Summary</h3>
                  <p><strong>Scan ID:</strong> {threats.scan_id}</p>
                  <p><strong>Threats Found:</strong> {threats.threats_found}</p>
                  <p><strong>Total Risk:</strong> <span className="risk-value">{threats.total_risk}</span></p>
                  <p><strong>Scan Time:</strong> {threats.scan_time}</p>
                </div>

                <div className="threats-list">
                  <h3>Detailed Findings</h3>
                  {threats.details.map((threat, index) => (
                    <div key={index} className="threat-card" style={{borderLeftColor: severityColors[threat.severity]}}>
                      <div className="threat-header">
                        <h4>{threat.type}</h4>
                        <span 
                          className="severity-badge"
                          style={{backgroundColor: severityColors[threat.severity]}}
                        >
                          {threat.severity}
                        </span>
                      </div>
                      <div className="threat-details">
                        <p><strong>Instance:</strong> {threat.instance_name} ({threat.instance})</p>
                        <p><strong>Impact:</strong> {threat.impact}</p>
                        <p><strong>Confidence:</strong> {threat.confidence}</p>
                        <p><strong>Business Impact:</strong> {threat.business_impact}</p>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="action-section">
                  <button onClick={simulateFix} className="fix-btn">
                    🛠️ Simulate Threat Remediation
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'costs' && costAnalysis && (
          <div className="costs-tab">
            <h2>💰 Cost Optimization Analysis</h2>
            
            <div className="cost-summary">
              <div className="cost-card">
                <h3>Current Monthly Spend</h3>
                <div className="cost-value">{costAnalysis.total_monthly_spend}</div>
              </div>
              <div className="cost-card">
                <h3>Potential Savings</h3>
                <div className="savings-value">{costAnalysis.potential_savings}/month</div>
              </div>
              <div className="cost-card">
                <h3>Annual Impact</h3>
                <div className="annual-value">{costAnalysis.annual_impact}</div>
              </div>
            </div>

            <div className="recommendations">
              <h3>💡 Optimization Recommendations</h3>
              {costAnalysis.recommendations.map((rec, index) => (
                <div key={index} className="recommendation-card">
                  <div className="rec-content">
                    <h4>{rec.recommendation}</h4>
                    <div className="rec-metrics">
                      <span className="savings">Savings: {rec.potential_savings}</span>
                      <span className={`confidence ${rec.confidence.toLowerCase()}`}>
                        Confidence: {rec.confidence}
                      </span>
                    </div>
                    <p className="business-impact">{rec.business_translation}</p>
                  </div>
                </div>
              ))}
            </div>

            <div className="business-impact">
              <h3>📈 Business Impact</h3>
              <p>{costAnalysis.business_impact}</p>
            </div>
          </div>
        )}

        {activeTab === 'executive' && executiveSummary && (
          <div className="executive-tab">
            <h2>📈 Executive Summary</h2>
            
            <div className="executive-overview">
              <h3>Executive Overview</h3>
              <div className="overview-grid">
                <div className="overview-card">
                  <h4>Security Rating</h4>
                  <div className="overview-value">{executiveSummary.executive_overview.security_rating}</div>
                </div>
                <div className="overview-card">
                  <h4>Cost Efficiency</h4>
                  <div className="overview-value">{executiveSummary.executive_overview.cost_efficiency}</div>
                </div>
                <div className="overview-card">
                  <h4>Compliance Status</h4>
                  <div className="overview-status">{executiveSummary.executive_overview.compliance_status}</div>
                </div>
                <div className="overview-card">
                  <h4>Overall Health</h4>
                  <div className="overview-health">{executiveSummary.executive_overview.overall_health}</div>
                </div>
              </div>
            </div>

            <div className="key-findings">
              <h3>Key Findings</h3>
              <div className="findings-grid">
                <div className="finding-card critical">
                  <h4>Critical Threats</h4>
                  <div className="finding-value">{executiveSummary.key_findings.critical_threats}</div>
                </div>
                <div className="finding-card high">
                  <h4>High Risks</h4>
                  <div className="finding-value">{executiveSummary.key_findings.high_risks}</div>
                </div>
                <div className="finding-card waste">
                  <h4>Monthly Waste</h4>
                  <div className="finding-value">{executiveSummary.key_findings.monthly_waste}</div>
                </div>
                <div className="finding-card compliance">
                  <h4>Compliance Gaps</h4>
                  <div className="finding-value">{executiveSummary.key_findings.compliance_gaps}</div>
                </div>
              </div>
            </div>

            <div className="recommended-actions">
              <h3>Recommended Actions</h3>
              <ul>
                {executiveSummary.recommended_actions.map((action, index) => (
                  <li key={index}>{action}</li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {activeTab === 'assessment' && (
          <div className="assessment-tab">
            <h2>🔒 Free Threat Assessment</h2>
            <div className="assessment-content">
              <div className="assessment-info">
                <h3>What You'll Get:</h3>
                <ul>
                  <li>✅ Comprehensive threat analysis of your AWS environment</li>
                  <li>✅ Cost optimization recommendations</li>
                  <li>✅ Compliance gap identification</li>
                  <li>✅ 30-minute executive briefing</li>
                  <li>✅ Customized remediation plan</li>
                </ul>
                <p className="assessment-note">
                  No obligation - just insights that could save your business thousands.
                </p>
              </div>

              <form onSubmit={submitAssessment} className="assessment-form">
                <div className="form-group">
                  <label>Full Name *</label>
                  <input
                    type="text"
                    required
                    value={assessmentForm.name}
                    onChange={(e) => setAssessmentForm({...assessmentForm, name: e.target.value})}
                    placeholder="Enter your full name"
                  />
                </div>

                <div className="form-group">
                  <label>Work Email *</label>
                  <input
                    type="email"
                    required
                    value={assessmentForm.email}
                    onChange={(e) => setAssessmentForm({...assessmentForm, email: e.target.value})}
                    placeholder="Enter your work email"
                  />
                </div>

                <div className="form-group">
                  <label>Company *</label>
                  <input
                    type="text"
                    required
                    value={assessmentForm.company}
                    onChange={(e) => setAssessmentForm({...assessmentForm, company: e.target.value})}
                    placeholder="Enter your company name"
                  />
                </div>

                <div className="form-group">
                  <label>Monthly AWS Spend (Optional)</label>
                  <select
                    value={assessmentForm.aws_spend}
                    onChange={(e) => setAssessmentForm({...assessmentForm, aws_spend: e.target.value})}
                  >
                    <option value="">Select range</option>
                    <option value="1k-5k">$1k - $5k</option>
                    <option value="5k-20k">$5k - $20k</option>
                    <option value="20k-50k">$20k - $50k</option>
                    <option value="50k+">$50k+</option>
                  </select>
                </div>

                <button type="submit" className="submit-btn">
                  🚀 Request Free Assessment
                </button>
              </form>
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <footer className="app-footer">
        <p>Spectraine - Cloud Threat Detection & Cost Optimization</p>
        <p>Demo Mode | No AWS Account Required</p>
      </footer>
    </div>
  );
}

export default App;