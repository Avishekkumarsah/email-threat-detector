import React, { useState, useRef } from 'react';
import { Upload, FileText, ArrowRight, ShieldCheck, AlertCircle, Loader2 } from 'lucide-react';
import { api } from '../api';
import type { ScanDetail } from '../api';

interface ScannerViewProps {
  onScanComplete: (scan: ScanDetail) => void;
  onOpenAuth: () => void;
  isAuthenticated: boolean;
}

export const ScannerView: React.FC<ScannerViewProps> = ({
  onScanComplete,
  onOpenAuth,
  isAuthenticated,
}) => {
  const [mode, setMode] = useState<'upload' | 'paste'>('upload');
  const [dragOver, setDragOver] = useState(false);
  const [rawText, setRawText] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState<string>('');
  const [error, setError] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
      if (['.eml', '.txt'].includes(ext)) {
        setSelectedFile(file);
        setError(null);
      } else {
        setError('Please drop a valid .eml or .txt email file.');
      }
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleStartScan = async () => {
    if (!isAuthenticated) {
      onOpenAuth();
      return;
    }

    setError(null);
    setIsScanning(true);

    try {
      setScanStep('Parsing RFC822 headers and extracting email body...');
      await new Promise((r) => setTimeout(r, 400));

      setScanStep('Executing scikit-learn TF-IDF phishing content classifier...');
      let result: ScanDetail;

      if (mode === 'upload') {
        if (!selectedFile) {
          throw new Error('Please select an .eml or .txt file to scan.');
        }
        result = await api.uploadScan(selectedFile);
      } else {
        if (!rawText.trim() || rawText.trim().length < 15) {
          throw new Error('Please paste a complete email source (headers and body).');
        }
        result = await api.analyzeSource(rawText);
      }

      setScanStep('Tracing delivery hops & computing composite threat score...');
      await new Promise((r) => setTimeout(r, 300));

      onScanComplete(result);
    } catch (err: any) {
      setError(err.message || 'Scanning failed');
    } finally {
      setIsScanning(false);
      setScanStep('');
    }
  };

  return (
    <div style={{ maxWidth: '860px', margin: '0 auto' }}>
      {/* Title */}
      <div style={{ textAlign: 'center', marginBottom: '32px' }}>
        <h1 style={{ fontSize: '32px', marginBottom: '8px' }}>
          Deep Email Threat & Phishing Scanner
        </h1>
        <p style={{ color: '#94a3b8', fontSize: '15px' }}>
          Upload a suspicious email (<code style={{ color: 'var(--accent-cyan)' }}>.eml</code> / <code style={{ color: 'var(--accent-cyan)' }}>.txt</code>)
          or paste RFC822 raw source to run multi-layer AI scoring, hop geolocation, and forensic evidence extraction.
        </p>
      </div>

      {/* Mode Tabs */}
      <div style={{ display: 'flex', justifyContent: 'center', gap: '8px', marginBottom: '24px' }}>
        <button
          onClick={() => { setMode('upload'); setError(null); }}
          className={`btn ${mode === 'upload' ? 'btn-primary' : 'btn-secondary'}`}
          style={{ padding: '8px 20px', borderRadius: '30px' }}
        >
          <Upload size={16} />
          File Upload (.eml / .txt)
        </button>
        <button
          onClick={() => { setMode('paste'); setError(null); }}
          className={`btn ${mode === 'paste' ? 'btn-primary' : 'btn-secondary'}`}
          style={{ padding: '8px 20px', borderRadius: '30px' }}
        >
          <FileText size={16} />
          Paste Raw Email Source
        </button>
      </div>

      {/* Error Alert */}
      {error && (
        <div style={{
          background: 'rgba(239, 68, 68, 0.15)',
          border: '1px solid rgba(239, 68, 68, 0.35)',
          borderRadius: '12px',
          padding: '12px 16px',
          marginBottom: '20px',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          color: '#fca5a5',
          fontSize: '14px',
        }}>
          <AlertCircle size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Scanner Card */}
      <div className="glass-panel" style={{ padding: '36px' }}>
        {mode === 'upload' ? (
          <div>
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileSelect}
              accept=".eml,.txt"
              style={{ display: 'none' }}
            />

            <div
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleFileDrop}
              onClick={() => fileInputRef.current?.click()}
              style={{
                border: `2px dashed ${dragOver ? 'var(--accent-cyan)' : selectedFile ? '#10b981' : 'rgba(255, 255, 255, 0.15)'}`,
                background: dragOver ? 'rgba(6, 182, 212, 0.08)' : selectedFile ? 'rgba(16, 185, 129, 0.05)' : 'rgba(15, 23, 42, 0.5)',
                borderRadius: '16px',
                padding: '48px 24px',
                textAlign: 'center',
                cursor: 'pointer',
                transition: 'all 200ms ease',
              }}
            >
              <div style={{
                width: '64px',
                height: '64px',
                borderRadius: '50%',
                background: selectedFile ? 'rgba(16, 185, 129, 0.2)' : 'rgba(6, 182, 212, 0.12)',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginBottom: '16px',
              }}>
                {selectedFile ? (
                  <ShieldCheck size={32} color="#10b981" />
                ) : (
                  <Upload size={30} color="var(--accent-cyan)" />
                )}
              </div>

              {selectedFile ? (
                <div>
                  <h3 style={{ fontSize: '18px', color: '#10b981', marginBottom: '6px' }}>
                    {selectedFile.name}
                  </h3>
                  <p style={{ color: '#94a3b8', fontSize: '13px' }}>
                    {(selectedFile.size / 1024).toFixed(1)} KB — Ready for analysis. Click or drop to change file.
                  </p>
                </div>
              ) : (
                <div>
                  <h3 style={{ fontSize: '18px', marginBottom: '8px' }}>
                    Drag & Drop your <span style={{ color: 'var(--accent-cyan)' }}>.eml</span> or <span style={{ color: 'var(--accent-cyan)' }}>.txt</span> file here
                  </h3>
                  <p style={{ color: '#94a3b8', fontSize: '13px', marginBottom: '14px' }}>
                    or browse files from your computer (Max 10 MB)
                  </p>
                  <button type="button" className="btn btn-secondary" style={{ pointerEvents: 'none' }}>
                    Select File
                  </button>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div>
            <label className="form-label">Paste Raw Email Source (Headers + Body)</label>
            <textarea
              rows={12}
              className="form-textarea font-mono"
              placeholder={`Delivered-To: victim@example.com\nReceived: from relay.spammer.net (relay.spammer.net [198.51.100.25])...\nFrom: "Security Alert" <urgent@security-paypa1.com>\nSubject: Immediate action required\n\nDear user, your account has been suspended...`}
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              style={{ fontSize: '12px', lineHeight: '1.6' }}
            />
          </div>
        )}

        {/* Scan Status Progress Indicator */}
        {isScanning && (
          <div style={{
            marginTop: '24px',
            padding: '16px',
            borderRadius: '12px',
            background: 'rgba(6, 182, 212, 0.1)',
            border: '1px solid rgba(6, 182, 212, 0.3)',
            display: 'flex',
            alignItems: 'center',
            gap: '14px',
          }}>
            <Loader2 size={24} color="var(--accent-cyan)" className="spin" style={{ animation: 'spin 1s linear infinite' }} />
            <div>
              <div style={{ fontWeight: 600, color: '#f8fafc', fontSize: '14px' }}>
                Analyzing Threat Vector...
              </div>
              <div style={{ fontSize: '12px', color: 'var(--accent-cyan)' }}>
                {scanStep}
              </div>
            </div>
          </div>
        )}

        {/* Submit Action */}
        <div style={{ marginTop: '28px', display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
          <button
            type="button"
            disabled={isScanning || (mode === 'upload' && !selectedFile) || (mode === 'paste' && !rawText.trim())}
            onClick={handleStartScan}
            className="btn btn-primary"
            style={{ padding: '12px 28px', fontSize: '15px' }}
          >
            {isScanning ? (
              <>
                <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} />
                Scanning in progress...
              </>
            ) : (
              <>
                Analyze Email
                <ArrowRight size={18} />
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
