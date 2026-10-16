#!/usr/bin/env python3
fpath = r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\frontend/components/command/HeroWorkflow.tsx'
with open(fpath, 'r') as f:
    lines = f.readlines()

# We want to replace lines 254-282 (0-indexed: 253-282) with new content
# Old lines 254-282:
# Line 254: "              {(scan.hasOutputFile || scan.downloadUrl) && scan.status === 'COMPLETED' && scan.artifactAuthorization === 'AUTHORIZED' && (\n"
# Line 255: '                <button\n'
# ... through
# Line 282: '              )}\n'

# New content for lines 254-282
new_block = [
    "              // Determine download eligibility based on artifact authorization level\n",
    "              const isAuthorized = scan.artifactAuthorization === 'AUTHORIZED';\n",
    "              const isUnverifiedDownload = scan.artifactAuthorization === 'UNVERIFIED_DOWNLOAD';\n",
    "              const isBlocked = scan.artifactAuthorization === 'BLOCKED' || (!isAuthorized && !isUnverifiedDownload);\n",
    "\n",
    "              // Show download button when authorized, or a warning-eligible button when unverified\n",
    "              const showDownloadBtn = isAuthorized || isUnverifiedDownload;\n",
    "              const showBlockedMsg = isBlocked && !(isUnverifiedDownload);\n",
    "\n",
    "              {showDownloadBtn && (\n",
    "                <div className={styles.downloadEligibility}>",
    "                  {isAuthorized && (\n",
    "                    <button\n",
    "                      className={cx(styles.heroBtn, styles.heroBtnPrimary)}\n",
    "                      onClick={requestDownload}\n",
    "                      disabled={ctx.downloadState.busy}\n",
    "                      style={{display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '8px', width: '100%', padding: '10px 16px', backgroundColor: 'var(--green)', color: '#0a0d14', fontWeight: 700, borderRadius: '6px', textDecoration: 'none', letterSpacing: '0.05em', cursor: ctx.downloadState.busy ? 'wait' : 'pointer', opacity: ctx.downloadState.busy ? 0.7 : 1}}\n",
    "                      title={ctx.downloadState.busy ? 'Downloading…' : 'Download the secured output file'}",
    "                    >",
    "                      <Icon name={ctx.downloadState.busy ? 'refresh' : 'download'} size={16} />",
    "                      {ctx.downloadState.busy\n",
    "                        ? 'DOWNLOADING…'\n",
    "                        : \`DOWNLOAD SECURED ${scan.uploadType === 'single_file' ? 'FILE' : 'REPOSITORY'}\`}",
    "                    </button>",
    "                  )}",
    "                  {isUnverifiedDownload && (\n",
    "                    <div className={styles.unverifiedDownloadWarning}>",
    "                      <Icon name=\"alertCircle\" size={16} style={{color: 'var(--orange)'}} />",
    "                      <span>UNVERIFIED DOWNLOAD</span>",
    "                      <span>This candidate has not been fully validated. ACE score: {scan.confidence !== undefined ? \`\${Number(scan.confidence).toFixed(1)}\%` : 'N/A'}.</span>",
    "                      <span>Validation status: {scan.results?.validation ? Object.values(scan.results.validation).flat().filter(Boolean).length > 0 ? 'See details' : 'UNVERIFIED' : 'UNVERIFIED'}.</span>",
    "                      <span>Security findings: {scan.stages.security?.details?.findings?.length || 0} unresolved.</span>",
    "                      <br />",
    "                      <small>Proceeding with download acknowledges that this code may contain unresolved security risks.</small>",
    "                      <br />",
    "                      <button\n",
    "                      className={styles.unverifiedAcknowledgementButton}\n",
    "                      onClick={() => { /* trigger acknowledgement modal */ }}\n",
    "                      disabled={ctx.downloadState.busy}",
    ">",
    "                        Acknowledge & Download",
    "                      </button>",
    "                    </div>",
    "                  )}",
    "                </div>",
    "              )}",
    "              {showBlockedMsg && (\n",
    "                <div className={styles.downloadBlockedMessage}>",
    "                  <Icon name=\"alertCircle\" size={16} style={{color: 'var(--red)'}} />",
    "                  <span>Download blocked</span>",
    "                  <span>This candidate cannot be downloaded because security remediation is incomplete or a critical vulnerability remains.</span>",
    "                </div>",
    "              )}",
]. 

# Wait, I made a syntax error - .split shouldn't be there. Let me fix this.
# Actually, the new_block list should just contain the lines, not be split.

# Let me just write the lines directly
new_lines_content = [
    "              // Determine download eligibility based on artifact authorization level",
    "              const isAuthorized = scan.artifactAuthorization === 'AUTHORIZED';",
    "              const isUnverifiedDownload = scan.artifactAuthorization === 'UNVERIFIED_DOWNLOAD';",
    "              const isBlocked = scan.artifactAuthorization === 'BLOCKED' || (!isAuthorized && !isUnverifiedDownload);",
    "",
    "              // Show download button when authorized, or a warning-eligible button when unverified",
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
    "                      style={{display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '8px', width: '100%', padding: '10px 16px', backgroundColor: 'var(--green)', color: '#0a0d14', fontWeight: 700, borderRadius: '6px', textDecoration: 'none', letterSpacing: '0.05em', cursor: ctx.downloadState.busy ? 'wait' : 'pointer', opacity: ctx.downloadState.busy ? 0.7 : 1}}",
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
    "                      <Icon name=\"alertCircle\" size={16} style={{color: 'var(--orange)'}} />",
    "                      <span>UNVERIFIED DOWNLOAD</span>",
    "                      <span>This candidate has not been fully validated. ACE score: {scan.confidence !== undefined ? `${Number(scan.confidence).toFixed(1)}%` : 'N/A'}.</span>",
    "                      <span>Validation status: {scan.results?.validation ? Object.values(scan.results.validation).flat().filter(Boolean).length > 0 ? 'See details' : 'UNVERIFIED' : 'UNVERIFIED'}.</span>",
    "                      <span>Security findings: {scan.stages.security?.details?.findings?.length || 0} unresolved.</span>",
    "                      <br />",
    "                      <small>Proceeding with download acknowledges that this code may contain unresolved security risks.</small>",
    "                      <br />",
    "                      <button\n",
    "                      className={styles.unverifiedAcknowledgementButton}",
    "                      onClick={() => { /* trigger acknowledgement modal */ }}",
    "                      disabled={ctx.downloadState.busy}",
    ">",
    "                        Acknowledge & Download",
    "                      </button>",
    "                    </div>",
    "                )}",
    "              )}",
    "              {showBlockedMsg && (",
    "                <div className={styles.downloadBlockedMessage}>",
    "                  <Icon name=\"alertCircle\" size={16} style={{color: 'var(--red)'}} />",
    "                  <span>Download blocked</span>",
    "                  <span>This candidate cannot be downloaded because security remediation is incomplete or a critical vulnerability remains.</span>",
    "                </div>",
    "              )}",
]. 

# Hmm, I'm getting syntax errors with the .split() call. Let me just write the content differently.
# Actually, let me take a completely different approach - use the edit tool with a very specific old string.

print("Need to use a different approach")