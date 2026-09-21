import fs from 'fs';
import path from 'path';
import AdmZip from 'adm-zip';

export interface ExtractionResult {
  totalFiles: number;
  totalSizeBytes: number;
  primaryLanguage: string;
  workspacePath: string;
}

export class UploadService {
  private static FORBIDDEN_NAMES = new Set([
    'CON', 'PRN', 'AUX', 'NUL',
    'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
    'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
  ]);

  private static EXTENSION_LANGUAGE_MAP: Record<string, string> = {
    '.ts': 'TypeScript',
    '.tsx': 'TypeScript',
    '.js': 'JavaScript',
    '.jsx': 'JavaScript',
    '.py': 'Python',
    '.java': 'Java',
    '.go': 'Go',
    '.cpp': 'C++',
    '.cc': 'C++',
    '.c': 'C',
    '.h': 'C/C++',
    '.cs': 'C#',
    '.rs': 'Rust',
    '.rb': 'Ruby',
    '.php': 'PHP',
    '.swift': 'Swift',
    '.kt': 'Kotlin',
  };

  /**
   * Validate file buffer/path magic bytes to ensure valid ZIP archive header
   */
  static validateZipHeader(filePath: string): boolean {
    if (!fs.existsSync(filePath)) return false;
    const buffer = Buffer.alloc(4);
    const fd = fs.openSync(filePath, 'r');
    try {
      fs.readSync(fd, buffer, 0, 4, 0);
      // ZIP magic numbers: PK\x03\x04 (0x504b0304), PK\x05\x06 (empty zip), PK\x07\x08 (spanned)
      const header = buffer.readUInt32BE(0);
      return header === 0x504b0304 || header === 0x504b0506 || header === 0x504b0708;
    } catch {
      return false;
    } finally {
      fs.closeSync(fd);
    }
  }

  /**
   * Safely extract ZIP archive into destination directory enforcing Zip Slip protection
   */
  static safeExtractZip(zipFilePath: string, destinationDir: string): ExtractionResult {
    // 1. Verify header
    if (!this.validateZipHeader(zipFilePath)) {
      throw new Error('Invalid archive format: File is corrupted or not a valid ZIP archive.');
    }

    const absDestDir = path.resolve(destinationDir);
    fs.mkdirSync(absDestDir, { recursive: true });

    let zip: AdmZip;
    try {
      zip = new AdmZip(zipFilePath);
    } catch (err: any) {
      throw new Error(`Failed to parse ZIP archive: ${err?.message || 'Corrupted archive'}`);
    }

    const zipEntries = zip.getEntries();
    if (zipEntries.length === 0) {
      throw new Error('Invalid archive: Uploaded ZIP archive is empty.');
    }

    let totalFiles = 0;
    let totalSizeBytes = 0;
    const extensionCounts: Record<string, number> = {};

    for (const entry of zipEntries) {
      const rawName = entry.entryName;
      // Normalize slashes
      const normalizedName = rawName.replace(/\\/g, '/');

      // Check for path traversal indicators
      if (normalizedName.includes('../') || normalizedName.includes('..\\')) {
        this.cleanupDirectory(absDestDir);
        throw new Error(`Malicious archive detected: Path traversal entry "${rawName}"`);
      }

      // Check absolute path resolution boundary (Zip Slip defense)
      const targetPath = path.resolve(absDestDir, normalizedName);
      if (!targetPath.startsWith(absDestDir + path.sep) && targetPath !== absDestDir) {
        this.cleanupDirectory(absDestDir);
        throw new Error(`Malicious archive detected: Zip Slip attack in entry "${rawName}"`);
      }

      // Check reserved OS device names
      const baseName = path.basename(targetPath).split('.')[0].toUpperCase();
      if (this.FORBIDDEN_NAMES.has(baseName)) {
        this.cleanupDirectory(absDestDir);
        throw new Error(`Malicious archive detected: Reserved OS filename "${rawName}"`);
      }

      if (entry.isDirectory) {
        fs.mkdirSync(targetPath, { recursive: true });
      } else {
        const parentDir = path.dirname(targetPath);
        if (!parentDir.startsWith(absDestDir + path.sep) && parentDir !== absDestDir) {
          this.cleanupDirectory(absDestDir);
          throw new Error(`Malicious archive detected: Invalid target directory "${rawName}"`);
        }
        fs.mkdirSync(parentDir, { recursive: true });

        const contentBuffer = entry.getData();
        fs.writeFileSync(targetPath, contentBuffer, { mode: 0o644 });

        totalFiles++;
        totalSizeBytes += contentBuffer.length;

        const ext = path.extname(targetPath).toLowerCase();
        if (ext) {
          extensionCounts[ext] = (extensionCounts[ext] || 0) + 1;
        }
      }
    }

    const primaryLanguage = this.detectPrimaryLanguage(extensionCounts);

    return {
      totalFiles,
      totalSizeBytes,
      primaryLanguage,
      workspacePath: absDestDir,
    };
  }

  /**
   * Detect primary programming language from file extensions
   */
  private static detectPrimaryLanguage(extensionCounts: Record<string, number>): string {
    let topLanguage = 'Generic / Multilingual';
    let maxCount = 0;

    const languageCounts: Record<string, number> = {};
    for (const [ext, count] of Object.entries(extensionCounts)) {
      const lang = this.EXTENSION_LANGUAGE_MAP[ext];
      if (lang) {
        languageCounts[lang] = (languageCounts[lang] || 0) + count;
      }
    }

    for (const [lang, count] of Object.entries(languageCounts)) {
      if (count > maxCount) {
        maxCount = count;
        topLanguage = lang;
      }
    }

    return topLanguage;
  }

  /**
   * Safely delete a file if exists
   */
  static cleanupFile(filePath: string): void {
    try {
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    } catch (err) {
      console.warn(`[UploadService] Warning: Failed to clean up temporary file ${filePath}:`, err);
    }
  }

  /**
   * Safely remove a directory recursively if exists
   */
  static cleanupDirectory(dirPath: string): void {
    try {
      if (fs.existsSync(dirPath)) {
        fs.rmSync(dirPath, { recursive: true, force: true });
      }
    } catch (err) {
      console.warn(`[UploadService] Warning: Failed to clean up directory ${dirPath}:`, err);
    }
  }
}
