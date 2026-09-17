import React, { useState, useEffect } from 'react'
import {
  ShieldAlert,
  ShieldCheck,
  UploadCloud,
  FileCode2,
  Table2,
  Copy,
  Check,
  AlertTriangle,
  Info,
  CheckCircle2,
  Server,
  FileText
} from 'lucide-react'

// Realistic preset templates for instant demonstration
const PRESETS = [
  {
    name: '🔴 Public GCS Bucket (Violation)',
    data: {
      resource_type: 'storage.googleapis.com/Bucket',
      resource_name: 'prod-customer-finance-records',
      public_access_prevention: 'unspecified',
      uniform_bucket_level_access: false,
      encryption_type: 'GOOGLE_MANAGED',
      versioning_enabled: false,
      logging_enabled: false,
    }
  },
  {
    name: '🟢 Compliant Storage Vault (Pass)',
    data: {
      resource_type: 'storage.googleapis.com/Bucket',
      resource_name: 'sec-ops-compliance-archive',
      public_access_prevention: 'enforced',
      uniform_bucket_level_access: true,
      encryption_type: 'CMEK',
      versioning_enabled: true,
      logging_enabled: true,
    }
  },
  {
    name: '🟡 Public Cloud SQL (Warning)',
    data: {
      resource_type: 'sqladmin.googleapis.com/Instance',
      resource_name: 'production-postgres-db',
      require_ssl: false,
      authorized_networks: ['0.0.0.0/0'],
      additional_attributes: {
        automated_backups: 'Disabled'
      }
    }
  }
]

export default function App() {
  const [activeTab, setActiveTab] = useState('config-audit')
  const [config, setConfig] = useState(PRESETS[0].data)
  const [framework, setFramework] = useState('CIS Google Cloud Foundations Benchmark v3.0')
  const [loading, setLoading] = useState(false)
  const [auditResult, setAuditResult] = useState(null)
  const [screenshotData, setScreenshotData] = useState(null)
  const [selectedFile, setSelectedFile] = useState(null)
  const [filePreview, setFilePreview] = useState(null)
  const [copiedIndex, setCopiedIndex] = useState(null)
  const [systemStatus, setSystemStatus] = useState(null)
  const [errorMessage, setErrorMessage] = useState(null)

  // Fetch API health
  useEffect(() => {
    fetch('/health')
      .then(res => res.json())
      .then(data => setSystemStatus(data))
      .catch(() => setSystemStatus({ status: 'offline' }))
  }, [])

  const handlePresetSelect = (preset) => {
    setConfig(preset.data)
    setAuditResult(null)
    setErrorMessage(null)
  }

  // Structured Config Audit
  const handleConfigAudit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setErrorMessage(null)
    setAuditResult(null)

    try {
      const response = await fetch('/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          resource_config: config,
          compliance_framework: framework,
        }),
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.detail || 'Audit request failed.')
      }

      const data = await response.json()
      setAuditResult(data)
    } catch (err) {
      setErrorMessage(err.message)
    } finally {
      setLoading(false)
    }
  }

  // Multimodal Screenshot Audit
  const handleFileChange = (e) => {
    const file = e.target.files[0]
    if (file) {
      setSelectedFile(file)
      setFilePreview(URL.createObjectURL(file))
      setScreenshotData(null)
      setAuditResult(null)
      setErrorMessage(null)
    }
  }

  const handleScreenshotAudit = async (e) => {
    e.preventDefault()
    if (!selectedFile) return

    setLoading(true)
    setErrorMessage(null)

    const formData = new FormData()
    formData.append('file', selectedFile)
    formData.append('compliance_framework', framework)

    try {
      const response = await fetch('/audit-from-screenshot', {
        method: 'POST',
        body: formData,
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.detail || 'Screenshot audit failed.')
      }

      const data = await response.json()
      setScreenshotData(data)
      setAuditResult(data.audit_result)
    } catch (err) {
      setErrorMessage(err.message)
    } finally {
      setLoading(false)
    }
  }

  const copyCommand = (text, index) => {
    navigator.clipboard.writeText(text)
    setCopiedIndex(index)
    setTimeout(() => setCopiedIndex(null), 2000)
  }

  return (
    <div className="app-container">
      {/* Top Application Header */}
      <header className="app-header">
        <div className="brand-section">
          <div className="brand-icon">
            <ShieldCheck size={26} />
          </div>
          <div>
            <h1 className="brand-title">CloudGuard AI</h1>
            <p className="brand-subtitle">Automated Compliance & Policy RAG Agent for Google Cloud Platform</p>
          </div>
        </div>

        <div className="header-badges">
          <span className="badge">
            <Server size={14} /> LangChain LCEL
          </span>
          <span className="badge">
            <FileText size={14} /> Vertex AI RAG
          </span>
          <span className={`badge ${systemStatus?.status === 'healthy' ? 'success' : ''}`}>
            ● {systemStatus?.status === 'healthy' ? 'API Connected' : 'Checking Backend'}
          </span>
        </div>
      </header>

      {/* Tabs */}
      <nav className="tab-bar">
        <button
          className={`tab-button ${activeTab === 'config-audit' ? 'active' : ''}`}
          onClick={() => setActiveTab('config-audit')}
        >
          <FileCode2 size={18} /> Cloud Config Audit
        </button>
        <button
          className={`tab-button ${activeTab === 'screenshot-audit' ? 'active' : ''}`}
          onClick={() => setActiveTab('screenshot-audit')}
        >
          <UploadCloud size={18} /> Console Screenshot Audit
        </button>
        <button
          className={`tab-button ${activeTab === 'guide' ? 'active' : ''}`}
          onClick={() => setActiveTab('guide')}
        >
          <Table2 size={18} /> Architecture & How It Works
        </button>
      </nav>

      {/* Content Area */}
      {activeTab !== 'guide' ? (
        <div className="workspace-grid">
          {/* Left Column: Form / Upload */}
          <div className="card">
            {activeTab === 'config-audit' ? (
              <form onSubmit={handleConfigAudit}>
                <div className="card-title">
                  <FileText size={20} color="#2563eb" /> Resource Configuration
                </div>
                <p className="card-desc">
                  Select a test preset below or customize the attributes to audit against compliance rulebooks.
                </p>

                {/* Quick Presets */}
                <div className="presets-container">
                  <div className="presets-label">Quick Test Presets:</div>
                  <div className="presets-buttons">
                    {PRESETS.map((preset, idx) => (
                      <button
                        key={idx}
                        type="button"
                        className="preset-btn"
                        onClick={() => handlePresetSelect(preset)}
                      >
                        {preset.name}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="form-field">
                  <label className="field-label">Compliance Rulebook</label>
                  <select
                    className="field-select"
                    value={framework}
                    onChange={(e) => setFramework(e.target.value)}
                  >
                    <option>CIS Google Cloud Foundations Benchmark v3.0</option>
                    <option>NIST Special Publication 800-53 (Rev. 5)</option>
                    <option>HIPAA Security Rule 45 CFR Part 164</option>
                    <option>PCI-DSS v4.0 Cloud Security Standards</option>
                  </select>
                </div>

                <div className="form-field">
                  <label className="field-label">Resource Name</label>
                  <input
                    type="text"
                    className="field-input"
                    value={config.resource_name || ''}
                    onChange={(e) => setConfig({ ...config, resource_name: e.target.value })}
                    required
                  />
                </div>

                <div className="form-field">
                  <label className="field-label">GCP Resource Type</label>
                  <input
                    type="text"
                    className="field-input"
                    value={config.resource_type || ''}
                    onChange={(e) => setConfig({ ...config, resource_type: e.target.value })}
                  />
                </div>

                {config.resource_type?.includes('Bucket') && (
                  <>
                    <div className="form-field">
                      <label className="field-label">Public Access Prevention</label>
                      <select
                        className="field-select"
                        value={config.public_access_prevention || 'unspecified'}
                        onChange={(e) => setConfig({ ...config, public_access_prevention: e.target.value })}
                      >
                        <option value="enforced">enforced (Secure / Compliant)</option>
                        <option value="unspecified">unspecified (Public Access Risk)</option>
                        <option value="inherited">inherited</option>
                      </select>
                    </div>

                    <div className="form-field">
                      <label className="field-label">Uniform Bucket-Level Access (UBLA)</label>
                      <select
                        className="field-select"
                        value={config.uniform_bucket_level_access ? 'true' : 'false'}
                        onChange={(e) => setConfig({ ...config, uniform_bucket_level_access: e.target.value === 'true' })}
                      >
                        <option value="true">Enabled (Unified IAM)</option>
                        <option value="false">Disabled (Object ACLs risk)</option>
                      </select>
                    </div>

                    <div className="form-field">
                      <label className="field-label">Encryption Key Type</label>
                      <select
                        className="field-select"
                        value={config.encryption_type || 'GOOGLE_MANAGED'}
                        onChange={(e) => setConfig({ ...config, encryption_type: e.target.value })}
                      >
                        <option value="CMEK">CMEK (Customer-Managed Key in Cloud KMS)</option>
                        <option value="GOOGLE_MANAGED">Google-Managed Default</option>
                        <option value="NONE">None</option>
                      </select>
                    </div>
                  </>
                )}

                <button type="submit" className="btn-primary" disabled={loading}>
                  {loading ? (
                    <>
                      <div className="spinner-small"></div> Evaluating Compliance...
                    </>
                  ) : (
                    <>
                      <ShieldCheck size={18} /> Run Compliance Audit
                    </>
                  )}
                </button>
              </form>
            ) : (
              /* Screenshot Upload Tab */
              <form onSubmit={handleScreenshotAudit}>
                <div className="card-title">
                  <UploadCloud size={20} color="#2563eb" /> Screenshot Config Extraction
                </div>
                <p className="card-desc">
                  Upload a Google Cloud Console settings screenshot. Gemini Vision will extract the visible settings,
                  which will then be evaluated by the compliance agent.
                </p>

                <div className="upload-zone" onClick={() => document.getElementById('fileInput').click()}>
                  <input
                    id="fileInput"
                    type="file"
                    accept="image/*"
                    style={{ display: 'none' }}
                    onChange={handleFileChange}
                  />
                  <UploadCloud size={36} color="#2563eb" style={{ margin: '0 auto 0.75rem auto' }} />
                  <p style={{ fontWeight: 600, color: '#0f172a', marginBottom: '0.2rem' }}>
                    {selectedFile ? selectedFile.name : 'Click or drop cloud console screenshot here'}
                  </p>
                  <p style={{ fontSize: '0.8rem', color: '#64748b' }}>
                    Supports PNG, JPEG, or WebP
                  </p>
                </div>

                {filePreview && (
                  <div style={{ marginBottom: '1rem' }}>
                    <img
                      src={filePreview}
                      alt="Preview"
                      style={{
                        width: '100%',
                        maxHeight: '200px',
                        objectFit: 'cover',
                        borderRadius: '8px',
                        border: '1px solid #e2e8f0'
                      }}
                    />
                  </div>
                )}

                <button type="submit" className="btn-primary" disabled={!selectedFile || loading}>
                  {loading ? (
                    <>
                      <div className="spinner-small"></div> Extracting & Auditing...
                    </>
                  ) : (
                    <>
                      <UploadCloud size={18} /> Extract Settings & Audit
                    </>
                  )}
                </button>
              </form>
            )}

            {/* Error Message Box */}
            {errorMessage && (
              <div style={{
                marginTop: '1.25rem',
                padding: '0.85rem 1rem',
                background: '#fef2f2',
                border: '1px solid #fecaca',
                borderRadius: '8px',
                color: '#b91c1c',
                fontSize: '0.86rem'
              }}>
                <div style={{ fontWeight: 600, marginBottom: '0.25rem' }}>Audit Error</div>
                <div>{errorMessage}</div>
              </div>
            )}
          </div>

          {/* Right Column: Audit Scorecard */}
          <div className="card">
            {auditResult ? (
              <div>
                <div className="scorecard-header">
                  <div>
                    <span className={`status-badge ${auditResult.scorecard.status.toLowerCase()}`}>
                      {auditResult.scorecard.status === 'PASS' ? (
                        <CheckCircle2 size={16} />
                      ) : (
                        <AlertTriangle size={16} />
                      )}
                      {auditResult.scorecard.status}
                    </span>
                    <span className={`risk-tag ${auditResult.scorecard.risk_level.toLowerCase()}`}>
                      Risk: {auditResult.scorecard.risk_level}
                    </span>
                  </div>
                  <span style={{ fontSize: '0.84rem', color: '#64748b' }}>
                    Target: <strong style={{ color: '#0f172a' }}>{auditResult.resource_name}</strong>
                  </span>
                </div>

                {/* Multimodal Extraction Attribution */}
                {screenshotData && (
                  <div style={{
                    background: '#f8fafc',
                    border: '1px solid #e2e8f0',
                    padding: '0.75rem 1rem',
                    borderRadius: '8px',
                    fontSize: '0.82rem',
                    marginBottom: '1rem'
                  }}>
                    <div style={{ fontWeight: 600, color: '#1d4ed8', marginBottom: '0.25rem' }}>
                      Gemini Vision Attribution:
                    </div>
                    <div>
                      <span style={{ color: '#059669', fontWeight: 600 }}>✓ Extracted ({screenshotData.extracted_fields?.length || 0}):</span>{' '}
                      {screenshotData.extracted_fields?.join(', ') || 'None'}
                    </div>
                    <div style={{ marginTop: '0.2rem' }}>
                      <span style={{ color: '#64748b', fontWeight: 600 }}>○ Defaulted to Null ({screenshotData.null_fields?.length || 0}):</span>{' '}
                      {screenshotData.null_fields?.join(', ') || 'None'}
                    </div>
                  </div>
                )}

                {/* Summary */}
                <div className="summary-callout">
                  <strong>Findings Summary:</strong> {auditResult.scorecard.summary}
                </div>

                {/* Violations List */}
                {auditResult.scorecard.violations && auditResult.scorecard.violations.length > 0 && (
                  <div>
                    <h3 style={{ fontSize: '0.98rem', fontWeight: 600, marginBottom: '0.75rem', color: '#0f172a' }}>
                      Identified Policy Breaches ({auditResult.scorecard.violations.length})
                    </h3>

                    {auditResult.scorecard.violations.map((violation, idx) => (
                      <div key={idx} className="violation-item">
                        <div className="violation-header">
                          <span className="rule-code">[{violation.rule_id}]</span>
                          <span className={`risk-tag ${violation.severity.toLowerCase()}`}>
                            {violation.severity}
                          </span>
                        </div>
                        <p style={{ fontSize: '0.9rem', color: '#334155', marginBottom: '0.35rem' }}>
                          {violation.description}
                        </p>

                        {violation.citation && (
                          <div className="citation-badge">
                            <Info size={13} /> {violation.citation}
                          </div>
                        )}

                        {violation.remediation && (
                          <div className="command-box">
                            <span>{violation.remediation}</span>
                            <button
                              className="copy-button"
                              title="Copy gcloud CLI command"
                              onClick={() => copyCommand(violation.remediation, idx)}
                            >
                              {copiedIndex === idx ? <Check size={16} color="#4ade80" /> : <Copy size={16} />}
                            </button>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {/* Remediation steps checklist */}
                {auditResult.scorecard.remediation_steps && auditResult.scorecard.remediation_steps.length > 0 && (
                  <div style={{ marginTop: '1.25rem' }}>
                    <h4 style={{ fontSize: '0.88rem', fontWeight: 600, color: '#334155', marginBottom: '0.4rem' }}>
                      Recommended Remediation Checklist:
                    </h4>
                    <ul style={{ paddingLeft: '1.25rem', fontSize: '0.84rem', color: '#64748b' }}>
                      {auditResult.scorecard.remediation_steps.map((step, idx) => (
                        <li key={idx} style={{ marginBottom: '0.25rem' }}>{step}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Google Sheets Status */}
                <div className={`sheet-banner ${auditResult.logged_to_sheet ? 'synced' : 'idle'}`}>
                  <Table2 size={16} />
                  <span>
                    {auditResult.logged_to_sheet
                      ? '✓ Successfully appended to Google Sheets Audit Log'
                      : '○ Google Workspace Sheets logging idle (Add credentials.json to auto-sync)'}
                  </span>
                </div>
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '3.5rem 1.5rem', color: '#64748b' }}>
                <ShieldCheck size={44} color="#94a3b8" style={{ margin: '0 auto 0.75rem auto' }} />
                <h3 style={{ color: '#334155', fontSize: '1.05rem', marginBottom: '0.4rem' }}>
                  No Audit Conducted Yet
                </h3>
                <p style={{ fontSize: '0.88rem' }}>
                  Choose a preset or upload a cloud console screenshot to trigger a compliance audit.
                </p>
              </div>
            )}
          </div>
        </div>
      ) : (
        /* Architecture & Interview Guide Tab */
        <div className="card" style={{ padding: '2rem' }}>
          <h2 style={{ fontSize: '1.3rem', fontWeight: 700, marginBottom: '1.25rem', color: '#0f172a' }}>
            System Architecture & Google Cloud AI Defensibility
          </h2>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginBottom: '1.5rem' }}>
            <div style={{ background: '#f8fafc', padding: '1.25rem', borderRadius: '10px', border: '1px solid #e2e8f0' }}>
              <h3 style={{ fontSize: '1rem', color: '#1d4ed8', marginBottom: '0.5rem' }}>
                1. LangChain Orchestration Layer
              </h3>
              <p style={{ fontSize: '0.88rem', color: '#475569', lineHeight: 1.6 }}>
                LangChain decouples prompt templating and variable injection from FastAPI endpoints, assembling
                standardized <code>PromptTemplate</code> → <code>RunnableLambda(ask_agent)</code> → <code>OutputParser</code> pipelines.
              </p>
            </div>

            <div style={{ background: '#f8fafc', padding: '1.25rem', borderRadius: '10px', border: '1px solid #e2e8f0' }}>
              <h3 style={{ fontSize: '1rem', color: '#1d4ed8', marginBottom: '0.5rem' }}>
                2. Real Vertex AI RAG Datastore
              </h3>
              <p style={{ fontSize: '0.88rem', color: '#475569', lineHeight: 1.6 }}>
                Queries official compliance benchmarks (e.g. CIS Google Cloud Benchmark v3.0) indexed inside a Vertex AI Agent Builder Datastore,
                returning authoritative citations alongside verdicts.
              </p>
            </div>
          </div>

          <div style={{ background: '#f8fafc', padding: '1.25rem', borderRadius: '10px', border: '1px solid #e2e8f0' }}>
            <h3 style={{ fontSize: '1rem', color: '#1d4ed8', marginBottom: '0.5rem' }}>
              3. Serverless Deployment on Cloud Run
            </h3>
            <p style={{ fontSize: '0.88rem', color: '#475569', lineHeight: 1.6 }}>
              Production deployment targets Google Cloud Run: scales to zero when idle, handles high concurrency,
              and authenticates to Vertex AI transparently via Cloud Run's Service Account and Application Default Credentials (ADC).
            </p>
          </div>
        </div>
      )}
    </div>
  )
}
