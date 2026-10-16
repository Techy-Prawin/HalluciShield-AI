fpath = r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\frontend/components/command/HeroWorkflow.tsx'
with open(fpath, 'r') as f:
    content = f.read()

# Find and replace the button section
old_pattern = """{showDownloadBtn && (
                <button
                  className={cx(styles.heroBtn, styles.heroBtnPrimary)}
                  onClick={requestDownload}
                  disabled={ctx.downloadState.busy}
                  style={{display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '8px', width: '100%', padding: '10px 16px', backgroundColor: 'var(--green)', color: '#0a0d14', fontWeight: 700, borderRadius: '6px', textDecoration: 'none', letterSpacing: '0.05em', cursor: ctx.downloadState.busy ? 'wait' : 'pointer', opacity: ctx.downloadState.busy ? 0.7 : 1}}
                  title={ctx.downloadState.busy ? 'Downloading…' : 'Download the secured output file'}
                >
                  <Icon name={ctx.downloadState.busy ? 'refresh' : 'download'} size={16} />
                  {ctx.downloadState.busy
                    ? 'DOWNLOADING…'
                    : `DOWNLOAD SECURED ${scan.uploadType === 'single_file' ? 'FILE' : 'REPOSITORY'}`}
                </button>
              )}

              {ctx.downloadState.error && ("""

new_pattern = """{showDownloadBtn && (
                <div className={styles.downloadEligibility}>
                  {isAuthorized && (
                    <button
                      className={cx(styles.heroBtn, styles.heroBtnPrimary)}
                      onClick={requestDownload}
                      disabled={ctx.downloadState.busy}
                      style={{
                        display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '8px', width: '100%', padding: '10px 16px', backgroundColor: 'var(--green)', color: '#0a0d14', fontWeight: 700, borderRadius: '6px', textDecoration: 'none', letterSpacing: '0.05em', cursor: ctx.downloadState.busy ? 'wait' : 'pointer', opacity: ctx.downloadState.busy ? 0.7 : 1}
                      }}
                      title={ctx.downloadState.busy ? 'Downloading…' : 'Download the secured output file'}
                    >
                      <Icon name={ctx.downloadState.busy ? 'refresh' : 'download'} size={16} />
                      {ctx.downloadState.busy
                        ? 'DOWNLOADING…'
                        : `DOWNLOAD SECURED ${scan.uploadType === 'single_file' ? 'FILE' : 'REPOSITORY'}`}
                    </button>
                  )}
                  {isUnverifiedDownload && (
                    <div className={styles.unverifiedDownloadWarning}>
                      <Icon name="alertCircle" size={16} style={{color: 'var(--orange)'}} />
                      <span>UNVERIFIED DOWNLOAD</span>
                      <span>This candidate has not been fully validated. ACE score: {scan.confidence !== undefined ? `{Number(scan.confidence).toFixed(1)}%` : 'N/A'}.</span>
                      <span>Validation status: {scan.results?.validation ? Object.values(scan.results.validation).flat().filter(Boolean).length > 0 ? 'See details' : 'UNVERIFIED' : 'UNVERIFIED'}.</span>
                      <span>Security findings: {scan.stages.security?.details?.findings?.length || 0} unresolved.</span>
                      <br />
                      <small>Proceeding with download acknowledges that this code may contain unresolved security risks.</small>
                      <br />
                      <button
                        className={styles.unverifiedAcknowledgementButton}
                        onClick={() => { /* trigger acknowledgement modal */ }}
                        disabled={ctx.downloadState.busy}
                      >
                        Acknowledge & Download
                      </button>
                    </div>
                  )}
                </div>
              )}
              {showBlockedMsg && (
                <div className={styles.downloadBlockedMessage}>
                  <Icon name="alertCircle" size={16} style={{color: 'var(--red)'}} />
                  <span>Download blocked</span>
                  <span>This candidate cannot be downloaded because security remediation is incomplete or a critical vulnerability remains.</span>
                </div>
              )}
            )}
            {ctx.downloadState.error && ("""

if old_pattern in content:
    content = content.replace(old_pattern, new_pattern)
    with open(fpath, 'w') as f:
        f.write(content)
    print('Replaced button section')
else:
    print('Old pattern not found')
    # Debug: print first 500 chars
    print('File starts with:', repr(content[:500]))