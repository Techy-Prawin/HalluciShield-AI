import request from 'supertest';
import fs from 'fs';
import path from 'path';
import AdmZip from 'adm-zip';
import { createApp } from '../src/app';
import { pool, checkDatabaseHealth } from '../src/config/db';
import { runMigrations } from '../src/db/migrate';
import { UploadService } from '../src/services/upload.service';

const app = createApp();

describe('Milestone 3: Secure Repository Upload API Suite', () => {
  const testDir = path.resolve(__dirname, 'temp_test_artifacts');
  let isDbAvailable = false;

  beforeAll(async () => {
    fs.mkdirSync(testDir, { recursive: true });
    const health = await checkDatabaseHealth();
    isDbAvailable = health.connected;
    if (isDbAvailable) {
      await runMigrations();
    }
  });

  afterAll(async () => {
    UploadService.cleanupDirectory(testDir);
    if (isDbAvailable) {
      await pool.end();
    }
  });

  /**
   * Helper function to create a test ZIP file
   */
  function createTestZip(zipPath: string, files: Record<string, string>): string {
    const zip = new AdmZip();
    for (const [filePath, content] of Object.entries(files)) {
      zip.addFile(filePath, Buffer.from(content, 'utf8'));
    }
    zip.writeZip(zipPath);
    return zipPath;
  }

  test('Valid Repository ZIP Upload (POST /api/repositories/upload)', async () => {
    const validZipPath = path.join(testDir, 'valid-repo.zip');
    createTestZip(validZipPath, {
      'src/index.ts': 'console.log("Hello HalluciShield");',
      'src/utils/math.ts': 'export const add = (a: number, b: number) => a + b;',
      'package.json': '{"name": "test-repo", "version": "1.0.0"}',
      'README.md': '# Test Repository',
    });

    const res = await request(app)
      .post('/api/repositories/upload')
      .attach('file', validZipPath)
      .field('name', 'my-custom-repo');

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.repository).toBeDefined();
    expect(res.body.repository.name).toBe('my-custom-repo');
    expect(res.body.repository.language).toBe('TypeScript');
    expect(res.body.repository.fileCount).toBe(4);
    expect(res.body.repository.status).toBe('INGESTED');
    expect(res.body.repository.workspacePath).toBeDefined();

    // Verify extracted files exist on disk
    const workspace = res.body.repository.workspacePath;
    expect(fs.existsSync(path.join(workspace, 'src/index.ts'))).toBe(true);
    expect(fs.existsSync(path.join(workspace, 'package.json'))).toBe(true);

    // Clean up extracted test workspace
    UploadService.cleanupDirectory(workspace);
    UploadService.cleanupFile(validZipPath);
  });

  test('Zip Slip / Path Traversal Attack Defense Rejection', async () => {
    const maliciousZipPath = path.join(testDir, 'zip-slip-attack.zip');
    
    // Create ZIP and explicitly inject relative path traversal in entry header
    const zip = new AdmZip();
    zip.addFile('valid.ts', Buffer.from('const x = 1;'));
    zip.addFile('placeholder.txt', Buffer.from('malicious payload'));
    
    const entries = zip.getEntries();
    const maliciousEntry = entries.find(e => e.entryName === 'placeholder.txt');
    if (maliciousEntry) {
      maliciousEntry.entryName = '../../../evil_shell.txt';
    }
    zip.writeZip(maliciousZipPath);

    const res = await request(app)
      .post('/api/repositories/upload')
      .attach('file', maliciousZipPath);

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toMatch(/Malicious archive detected|Path traversal/i);

    // Verify malicious file was NOT written outside target directory
    const escapeAttemptPath = path.resolve(__dirname, '../../../evil_shell.txt');
    expect(fs.existsSync(escapeAttemptPath)).toBe(false);

    UploadService.cleanupFile(maliciousZipPath);
  });

  test('Rejection of Invalid File Type (.txt file instead of .zip)', async () => {
    const textFilePath = path.join(testDir, 'not-a-zip.txt');
    fs.writeFileSync(textFilePath, 'This is plain text, not a zip file.');

    const res = await request(app)
      .post('/api/repositories/upload')
      .attach('file', textFilePath);

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toMatch(/Invalid file type/i);

    UploadService.cleanupFile(textFilePath);
  });

  test('Rejection of Corrupted Fake ZIP File (.zip extension but bad bytes)', async () => {
    const fakeZipPath = path.join(testDir, 'fake-header.zip');
    fs.writeFileSync(fakeZipPath, 'FAKE_HEADER_CONTENT_BYTES');

    const res = await request(app)
      .post('/api/repositories/upload')
      .attach('file', fakeZipPath);

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toMatch(/Invalid archive format|Corrupted/i);

    UploadService.cleanupFile(fakeZipPath);
  });

  test('Rejection of Request Without File Attachment', async () => {
    const res = await request(app).post('/api/repositories/upload');
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toMatch(/No archive file uploaded/i);
  });

  test('Zero Execution Guarantee (Uploaded code is untrusted and never executed)', async () => {
    const codeZipPath = path.join(testDir, 'untrusted-code.zip');
    createTestZip(codeZipPath, {
      'package.json': '{"scripts": {"postinstall": "exit 1"}}',
      'malicious.js': 'process.exit(1);',
    });

    const res = await request(app)
      .post('/api/repositories/upload')
      .attach('file', codeZipPath);

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);

    const workspace = res.body.repository.workspacePath;
    expect(fs.existsSync(path.join(workspace, 'malicious.js'))).toBe(true);

    // Clean up
    UploadService.cleanupDirectory(workspace);
    UploadService.cleanupFile(codeZipPath);
  });
});
