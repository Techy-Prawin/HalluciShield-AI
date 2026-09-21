'use client';

import React, { useState, useRef, DragEvent, ChangeEvent } from 'react';
import styles from './UploadPortal.module.css';

export interface RepositoryData {
  id: string;
  name: string;
  language: string;
  fileCount: number;
  status: string;
  workspacePath: string;
  createdAt: string;
}

interface UploadPortalProps {
  onScanRequested?: (repoId: string) => void;
  scanError?: string | null;
  scanning?: boolean;
}

export function UploadPortal({ onScanRequested, scanError, scanning }: UploadPortalProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState<'idle' | 'uploading' | 'success' | 'error'>('idle');
  const [uploadProgress, setUploadProgress] = useState(0);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [repository, setRepository] = useState<RepositoryData | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const backendUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const droppedFiles = e.dataTransfer.files;
    if (droppedFiles && droppedFiles.length > 0) {
      processSelectedFile(droppedFiles[0]);
    }
  };

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processSelectedFile(e.target.files[0]);
    }
  };

  const ALLOWED_EXTENSIONS = [
    '.zip', '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs', '.c', '.cpp', '.rb', '.php'
  ];

  const processSelectedFile = (selectedFile: File) => {
    const ext = '.' + selectedFile.name.toLowerCase().split('.').pop();
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      setStatus('error');
      setErrorMessage(`Invalid file type "${ext}". Please upload a .zip archive or source code file (.py, .js, .ts, .java, etc.).`);
      setFile(null);
      return;
    }

    if (selectedFile.size > 50 * 1024 * 1024) {
      setStatus('error');
      setErrorMessage('File size limit exceeded. Maximum file size is 50MB.');
      setFile(null);
      return;
    }

    setFile(selectedFile);
    setErrorMessage(null);
    uploadFile(selectedFile);
  };

  const uploadFile = (fileToUpload: File) => {
    setStatus('uploading');
    setUploadProgress(10);
    setErrorMessage(null);

    const formData = new FormData();
    formData.append('file', fileToUpload);

    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${backendUrl}/api/repositories/upload`, true);

    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) {
        const percent = Math.round((event.loaded / event.total) * 90);
        setUploadProgress(percent);
      }
    };

    xhr.onload = () => {
      setUploadProgress(100);
      try {
        const data = JSON.parse(xhr.responseText);
        if (xhr.status === 201 && data.success) {
          setRepository(data.repository);
          setStatus('success');
        } else {
          setStatus('error');
          setErrorMessage(data.error || 'Failed to upload repository archive.');
        }
      } catch (err) {
        setStatus('error');
        setErrorMessage('Invalid response from backend server.');
      }
    };

    xhr.onerror = () => {
      setStatus('error');
      setErrorMessage('Network error occurred during upload. Check backend server connection.');
    };

    xhr.send(formData);
  };

  const handleScanClick = () => {
    if (repository && onScanRequested) {
      onScanRequested(repository.id);
    } else if (repository) {
      alert(`Vulnerability Scan initiated for Repository ID: ${repository.id}`);
    }
  };

  const resetUpload = () => {
    setFile(null);
    setStatus('idle');
    setUploadProgress(0);
    setErrorMessage(null);
    setRepository(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <div className={styles.container}>
      <div className={styles.cardHeader}>
        <div>
          <h2 className={styles.cardTitle}>Repository Upload Portal</h2>
          <p className={styles.cardSubtitle}>
            Drag and drop a source code repository (.zip archive) for safe ingestion and multi-agent hallucination scanning.
          </p>
        </div>
        <span className={styles.securityBadge}>
          <svg className={styles.shieldIcon} viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          Zip Slip Protected
        </span>
      </div>

      {/* Drag & Drop Upload Zone */}
      {status !== 'success' && (
        <div
          className={`${styles.dropzone} ${isDragging ? styles.dropzoneActive : ''} ${status === 'error' ? styles.dropzoneError : ''}`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          role="region"
          aria-label="Repository Upload Dropzone"
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            accept=".zip,.py,.js,.ts,.jsx,.tsx,.java,.go,.rs,.c,.cpp,.rb,.php"
            className={styles.fileInput}
          />

          <div className={styles.dropzoneContent}>
            <div className={styles.uploadIconWrapper}>
              <svg className={styles.uploadIcon} viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
              </svg>
            </div>
            
            <h3 className={styles.dropzoneTitle}>
              {isDragging ? 'Drop repository ZIP or source file here' : 'Drag & drop repository ZIP or source code file'}
            </h3>
            <p className={styles.dropzoneDescription}>
              or <span className={styles.browseLink}>browse files</span> from your computer
            </p>
            <span className={styles.fileLimitNotice}>Supports .zip archives or single source files (.py, .js, .ts, etc.) up to 50MB</span>
          </div>
        </div>
      )}

      {/* Upload Progress Bar */}
      {status === 'uploading' && (
        <div className={styles.progressContainer}>
          <div className={styles.progressHeader}>
            <span className={styles.progressLabel}>
              {uploadProgress < 100 ? 'Uploading and validating source...' : 'Materializing workspace & preparing security scan...'}
            </span>
            <span className={styles.progressPercentage}>{uploadProgress}%</span>
          </div>
          <div className={styles.progressBarBackground}>
            <div
              className={styles.progressBarFill}
              style={{ width: `${uploadProgress}%` }}
            />
          </div>
        </div>
      )}

      {/* Error Alert */}
      {status === 'error' && errorMessage && (
        <div className={styles.errorAlert}>
          <div className={styles.errorHeader}>
            <svg className={styles.errorIcon} viewBox="0 0 24 24" fill="none" stroke="currentColor">
              <circle cx="12" cy="12" r="10" strokeWidth="2" />
              <line x1="12" y1="8" x2="12" y2="12" strokeWidth="2" strokeLinecap="round" />
              <line x1="12" y1="16" x2="12.01" y2="16" strokeWidth="2" strokeLinecap="round" />
            </svg>
            <span className={styles.errorTitle}>Upload Error</span>
          </div>
          <p className={styles.errorMessage}>{errorMessage}</p>
          <button className={styles.retryButton} onClick={resetUpload}>
            Try Again
          </button>
        </div>
      )}

      {/* Ingested Repository Information Card */}
      {status === 'success' && repository && (
        <div className={styles.repoCard}>
          <div className={styles.repoHeader}>
            <div className={styles.repoTitleBlock}>
              <span className={styles.statusBadgeSuccess}>INGESTED</span>
              <h3 className={styles.repoName}>{repository.name}</h3>
            </div>
            <button className={styles.resetLink} onClick={resetUpload}>
              Upload Another Repository
            </button>
          </div>

          <div className={styles.repoGrid}>
            <div className={styles.repoDetailItem}>
              <span className={styles.detailLabel}>Repository ID</span>
              <span className={styles.detailValueCode}>{repository.id}</span>
            </div>
            <div className={styles.repoDetailItem}>
              <span className={styles.detailLabel}>Primary Language</span>
              <span className={styles.languageBadge}>{repository.language}</span>
            </div>
            <div className={styles.repoDetailItem}>
              <span className={styles.detailLabel}>File Count</span>
              <span className={styles.detailValue}>{repository.fileCount} source files</span>
            </div>
            <div className={styles.repoDetailItem}>
              <span className={styles.detailLabel}>Workspace Location</span>
              <span className={styles.detailValueCode}>{repository.workspacePath}</span>
            </div>
          </div>

          <div className={styles.scanActionSection}>
            <div className={styles.scanNotice}>
              <svg className={styles.infoIcon} viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span>Repository isolated safely. Ready for multi-agent hallucination & vulnerability scan.</span>
            </div>

            <button
              className={styles.scanButton}
              onClick={handleScanClick}
              disabled={scanning}
              style={{ cursor: scanning ? 'wait' : 'pointer', opacity: scanning ? 0.7 : 1 }}
            >
              <svg className={styles.scanIcon} viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              {scanning ? 'Scan In Progress…' : 'Trigger Multi-Agent Vulnerability Scan'}
            </button>
            {scanError && <p role="alert">{scanError}</p>}
          </div>
        </div>
      )}
    </div>
  );
}
