import { Router, Request, Response, NextFunction } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { UploadService } from '../services/upload.service';
import { WorkspaceService } from '../services/workspace.service';
import { RepositoryModel, Repository } from '../models';
import { checkDatabaseHealth } from '../config/db';

const router = Router();

// Ensure temporary upload directory exists
const tempUploadDir = path.resolve(__dirname, '../../uploads/temp_archives');
fs.mkdirSync(tempUploadDir, { recursive: true });

/** File extensions accepted for single-file source uploads. */
const SINGLE_FILE_EXTENSIONS = new Set([
  '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs', '.c', '.cpp', '.rb', '.php', '.swift', '.kt',
]);

/** Map extension to language name. */
const EXT_LANGUAGE: Record<string, string> = {
  '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript', '.jsx': 'JavaScript',
  '.tsx': 'TypeScript', '.java': 'Java', '.go': 'Go', '.rs': 'Rust',
  '.c': 'C', '.cpp': 'C++', '.rb': 'Ruby', '.php': 'PHP', '.swift': 'Swift', '.kt': 'Kotlin',
};

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, tempUploadDir);
  },
  filename: (_req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const ext = path.extname(file.originalname).toLowerCase() || '.tmp';
    cb(null, `upload-${uniqueSuffix}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext === '.zip' || SINGLE_FILE_EXTENSIONS.has(ext)) return cb(null, true);
    return cb(new Error(
      `Invalid file type "${ext}". Accepted: .zip archives or single source files (${[...SINGLE_FILE_EXTENSIONS].join(', ')}).`
    ));
  },
});

/**
 * POST /api/repositories/upload
 *
 * Accepts either:
 * - A .zip repository archive (full project scan, zip-slip protected)
 * - A single source file (.py, .js, .ts, .java, etc.) for single-file scan
 *
 * For single files, creates a minimal workspace containing that one file so
 * the AI engine scan pipeline can process it identically to a ZIP workspace.
 * The upload_type in metadata is used by the orchestration pipeline to decide
 * which stages to mark NOT_APPLICABLE (e.g. dependency analysis for single files).
 */
router.post('/upload', (req: Request, res: Response, next: NextFunction) => {
  upload.single('file')(req, res, async (err: any) => {
    // Handle Multer / filter errors
    if (err) {
      if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ success: false, error: 'File size limit exceeded (max 50MB).' });
      }
      return res.status(400).json({ success: false, error: err.message || 'Failed to process file upload.' });
    }
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No archive file uploaded. Please upload a .zip archive or a single source file (.py, .js, .ts, .java, etc.) under the "file" form field.',
      });
    }

    const tempFilePath = req.file.path;
    const originalName = req.file.originalname;
    const ext = path.extname(originalName).toLowerCase();
    const isZip = ext === '.zip';
    const isSingleFile = SINGLE_FILE_EXTENSIONS.has(ext);
    const repoId = crypto.randomUUID();
    const extractedDir = WorkspaceService.runDir(repoId);
    const archivePath = WorkspaceService.archivePath(repoId);

    try {
      let extractionResult: { totalFiles: number; totalSizeBytes: number; primaryLanguage: string; workspacePath: string };
      let archiveStaged: string | undefined;

      if (isZip) {
        // ZIP archive flow — zip-slip protected extraction
        if (!UploadService.validateZipHeader(tempFilePath)) {
          throw new Error('Invalid archive format: File is corrupted or not a valid ZIP archive.');
        }
        // Stage archive on shared volume; scan re-materialization uses this copy
        fs.copyFileSync(tempFilePath, archivePath);
        archiveStaged = archivePath;
        extractionResult = UploadService.safeExtractZip(tempFilePath, extractedDir);
      } else if (isSingleFile) {
        // Single source file flow — create minimal one-file workspace
        fs.mkdirSync(extractedDir, { recursive: true });
        const destFilePath = path.join(extractedDir, originalName);
        fs.copyFileSync(tempFilePath, destFilePath);
        const fileStats = fs.statSync(destFilePath);
        extractionResult = {
          totalFiles: 1,
          totalSizeBytes: fileStats.size,
          primaryLanguage: EXT_LANGUAGE[ext] || 'Generic',
          workspacePath: extractedDir,
        };
        // No archive staged — workspace is a plain directory
        archiveStaged = undefined;
      } else {
        throw new Error(`Unsupported file type: ${ext}`);
      }

      const defaultName = path.basename(originalName, ext);
      const repoName =
        req.body?.name && typeof req.body.name === 'string' && req.body.name.trim()
          ? req.body.name.trim()
          : defaultName || `repository-${repoId.substring(0, 8)}`;

      const metadata: Record<string, unknown> = {
        repository_id: repoId,
        file_count: extractionResult.totalFiles,
        size_bytes: extractionResult.totalSizeBytes,
        workspace_path: extractionResult.workspacePath,
        archive_path: archiveStaged ?? null,
        uploaded_archive_name: originalName,
        original_file_name: originalName,
        // upload_type drives pipeline decisions (e.g. skip dependency analysis)
        upload_type: isZip ? 'archive' : 'single_file',
        status: 'INGESTED',
      };

      let repo: Repository;
      const dbHealth = await checkDatabaseHealth();
      if (dbHealth.connected) {
        repo = await RepositoryModel.create({
          name: repoName,
          url: `file://${extractionResult.workspacePath}`,
          default_branch: req.body?.branch || 'main',
          language: extractionResult.primaryLanguage,
          is_active: true,
          metadata,
        });
      } else {
        repo = {
          id: repoId,
          name: repoName,
          url: `file://${extractionResult.workspacePath}`,
          default_branch: req.body?.branch || 'main',
          language: extractionResult.primaryLanguage,
          is_active: true,
          metadata,
          created_at: new Date(),
          updated_at: new Date(),
        };
      }

      UploadService.cleanupFile(tempFilePath);

      return res.status(201).json({
        success: true,
        message: isZip
          ? 'Repository archive uploaded, validated, and ingested successfully.'
          : `Source file "${originalName}" uploaded and workspace prepared successfully.`,
        repository: {
          id: repo.id,
          name: repo.name,
          language: repo.language,
          fileCount: extractionResult.totalFiles,
          status: 'INGESTED',
          workspacePath: extractionResult.workspacePath,
          uploadType: isZip ? 'archive' : 'single_file',
          originalFileName: originalName,
          createdAt: repo.created_at,
        },
      });
    } catch (extractErr: any) {
      UploadService.cleanupFile(tempFilePath);
      UploadService.cleanupDirectory(extractedDir);
      console.error('[RepositoryRouter] Upload/extraction failed:', extractErr?.message);
      return res.status(400).json({
        success: false,
        error: extractErr?.message || 'Failed to process uploaded file.',
      });
    }
  });
});

export const repositoryRouter = router;
