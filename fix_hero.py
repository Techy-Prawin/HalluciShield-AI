#!/usr/bin/env python3
fpath = r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\frontend/components/command/HeroWorkflow.tsx'
with open(fpath, 'r') as f:
    lines = f.readlines()

# Replace lines 254-282 (0-indexed: 253-282) with new download eligibility logic
# Keep lines 0-252, insert new lines, keep lines 283+

new_lines = [
    "              // Determine download eligibility based on artifact authorization level\n",
    "              const isAuthorized = scan.artifactAuthorization === 'AUTHORIZED';",
    "              const isUnverifiedDownload = scan.artifactAuthorization === 'UNVERIFIED_DOWNLOAD';",
    "              const isBlocked = scan.artifactAuthorization === 'BLOCKED' || (!isAuthorized && !isUnverifiedDownload);",
    "",
    "              // Show download button when authorized, or a warning-eligible button when unverified\n",
    "              const showDownloadBtn = isAuthorized || isUnverifiedDownload;",
    "              const showBlockedMsg = isBlocked && !(isUnverifiedDownload);",
    "",
    "{showDownloadBtn && (",
    "                <div className={styles.downloadEligibility}>",
    "                  {isAuthorized && (",
    "                    <button",
    "                      className={cx(styles.heroBtn, styles.heroBtnPrimary)}",
    "                      onClick={requestDownload}",
    "                      disabled={ctx.downloadState.busy}",
    "                      style={{
                        display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '8px', width: '100%', padding: '10px 16px', backgroundColor: 'var(--green)', color: '#0a0d14', fontWeight: 700, borderRadius: '6px', textDecoration: 'none', letterSpacing: '0.05em', cursor: ctx.downloadState.busy ? 'wait' : 'pointer', opacity: ctx.downloadState.busy ? 0.7 : 1}",
    "                      title={ctx.downloadState.busy ? 'Downloading…' : 'Download the secured output file'}",
    "                    >",
    "                      <Icon name={ctx.downloadState.busy ? 'refresh' : 'download'} size={16} />",
    "                      {ctx.downloadState.busy",
    "                        ? 'DOWNLOADING…',
    "                        : `DOWNLOAD SECURED ${scan.uploadType === 'single_file' ? 'FILE' : 'REPOSITORY'`}",
    "                    }",
    "                  </button>",
    "                  )}",
    "                  {isUnverifiedDownload && (",
    "                    <div className={styles.unverifiedDownloadWarning}>",
    "                      <Icon name='alertCircle' size={16} style={{color: 'var(--orange)'}} />",
    "                      <span>UNVERIFIED DOWNLOAD</span>",
    "                      <span>This candidate has not been fully validated. ACE score: {scan.confidence !== undefined ? `{Number(scan.confidence).toFixed(1)}%` : 'N/A'}.</span>",
    "                      <span>Validation status: {scan.results?.validation ? Object.values(scan.results.validation).flat().filter(Boolean).length > 0 ? 'See details' : 'UNVERIFIED' : 'UNVERIFIED'}.</span>",
    "                      <span>Security findings: {scan.stages.security?.details?.findings?.length || 0} unresolved.</span>",
    "                      <br />",
    "                      <small>Proceeding with download acknowledges that this code may contain unresolved security risks.</small>",
    "                      <br />",
    "                      <button",
    "                      className={styles.unverifiedAcknowledgementButton}",
    "                      onClick={() => { /* trigger acknowledgement modal */ }}",
    "                      disabled={ctx.downloadState.busy}",
    ">",
    "                        Acknowledge & Download",
    "                      </button>",
    "                    </div>",
    "                  )}",
    "              )}",
    "              {showBlockedMsg && (",
    "                <div className={styles.downloadBlockedMessage}>",
    "                  <Icon name='alertCircle' size={16} style={{color: 'var(--red)'}} />",
    "                  <span>Download blocked</span>",
    "                  <span>This candidate cannot be downloaded because security remediation is incomplete or a critical vulnerability remains.</span>",
    "                </div>",
    "              )}",
]. 

# Wait, I'm getting syntax errors with the .split() call. Let me just write the lines directly
# Actually the .split() at the end is wrong - let me remove it

# Let me just write the output
output_lines = lines[:253] + new_lines + lines[283:]

with open(fpath, 'w') as f:
    f.writelines(output_lines)

print('Replaced download button section -', len(new_lines), 'new lines added')