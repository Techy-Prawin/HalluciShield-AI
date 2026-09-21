import * as fs from 'fs';
import * as path from 'path';
import { pipeline } from 'stream/promises';

export type HallucinationType =
  | 'NON_EXISTENT_PACKAGE'
  | 'SUSPICIOUS_IMPORT'
  | 'UNKNOWN_API'
  | 'UNKNOWN_FUNCTION'
  | 'INCORRECT_API_USAGE'
  | 'UNSUPPORTED_SECURITY_ASSUMPTION'
  | 'SUSPICIOUS_DEPENDENCY';

export type VerificationStatus =
  | 'CONFIRMED'
  | 'LIKELY'
  | 'SUSPICIOUS'
  | 'NOT_VERIFIED';

export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface HallucinationFinding {
  finding_id: string;
  type: HallucinationType;
  file: string;
  line: number;
  evidence: string[];
  explanation: string;
  severity: SeverityLevel;
  confidence: number;
  verification_method: string;
  verification_status: VerificationStatus;
}

export interface ExtractedElement {
  type: HallucinationType;
  name: string;
  file: string;
  line: number;
  snippet: string;
  context: string;
}

export interface VerificationResult {
  element: ExtractedElement;
  status: VerificationStatus;
  evidence: string[];
  confidence: number;
  details: Record<string, any>;
}

export interface LLMAnalysisRequest {
  elements: ExtractedElement[];
  verification_results: VerificationResult[];
  file_content: string;
}

export interface LLMAnalysisResponse {
  findings: HallucinationFinding[];
  reasoning: string;
  metadata: Record<string, any>;
}

const KNOWN_PACKAGES = new Set([
  'express', 'lodash', 'axios', 'react', 'vue', 'angular',
  'typescript', 'jest', 'mocha', 'chai', 'webpack', 'babel',
  'pg', 'mysql', 'mongodb', 'mongoose', 'sequelize', 'typeorm',
  'dotenv', 'cors', 'helmet', 'multer', 'jsonwebtoken', 'bcrypt',
  'redis', 'socket.io', 'graphql', 'apollo-server', 'prisma',
  'next', 'nuxt', 'gatsby', 'vite', 'esbuild', 'rollup'
]);

const KNOWN_GLOBAL_APIS = new Set([
  'console', 'document', 'window', 'navigator', 'fetch', 'XMLHttpRequest',
  'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval', 'Promise',
  'Array', 'Object', 'String', 'Number', 'Boolean', 'Date', 'RegExp',
  'Map', 'Set', 'WeakMap', 'WeakSet', 'Symbol', 'Proxy', 'Reflect',
  'Error', 'TypeError', 'RangeError', 'SyntaxError', 'ReferenceError',
  'JSON', 'Math', 'Intl', 'URL', 'URLSearchParams', 'FormData',
  'Headers', 'Request', 'Response', 'AbortController', 'AbortSignal',
  'Blob', 'File', 'FileReader', 'Worker', 'SharedWorker', 'ServiceWorker'
]);

const KNOWN_NODE_APIS = new Set([
  'fs', 'path', 'http', 'https', 'net', 'tls', 'crypto', 'zlib',
  'stream', 'events', 'url', 'querystring', 'util', 'os', 'child_process',
  'cluster', 'dgram', 'dns', 'domain', 'module', 'process', 'readline',
  'repl', 'string_decoder', 'sys', 'timers', 'tty', 'v8', 'vm', 'worker_threads'
]);

export class HallucinationDetectionService {
  private npmRegistryCache: Map<string, { exists: boolean; timestamp: number }> = new Map();
  private readonly CACHE_TTL = 5 * 60 * 1000;

  async detectHallucinations(
    files: { path: string; content: string }[]
  ): Promise<HallucinationFinding[]> {
    const allFindings: HallucinationFinding[] = [];

    for (const file of files) {
      const extracted = this.extractSuspiciousElements(file.content, file.path);
      const verified = await this.verifyElements(extracted, file.content);
      const findings = this.compileFindings(verified, file.path);
      allFindings.push(...findings);
    }

    return allFindings;
  }

  extractSuspiciousElements(content: string, filePath: string): ExtractedElement[] {
    const elements: ExtractedElement[] = [];
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      const requireMatches = line.match(/require\s*\(\s*['"]([^'"]+)['"]\s*\)/g);
      if (requireMatches) {
        requireMatches.forEach(match => {
          const pkg = match.match(/require\s*\(\s*['"]([^'"]+)['"]\s*\)/)?.[1];
          if (pkg) {
            elements.push({
              type: 'SUSPICIOUS_IMPORT',
              name: pkg,
              file: filePath,
              line: index + 1,
              snippet: line.trim(),
              context: this.getContext(lines, index)
            });
          }
        });
      }

      const importMatches = line.match(/import\s+.*?from\s+['"]([^'"]+)['"]/g);
      if (importMatches) {
        importMatches.forEach(match => {
          const pkg = match.match(/from\s+['"]([^'"]+)['"]/)?.[1];
          if (pkg && !pkg.startsWith('.')) {
            elements.push({
              type: 'SUSPICIOUS_IMPORT',
              name: pkg,
              file: filePath,
              line: index + 1,
              snippet: line.trim(),
              context: this.getContext(lines, index)
            });
          }
        });
      }

      const apiCallMatches = line.match(/(\w+)\s*\.\s*(\w+)\s*\(/g);
      if (apiCallMatches) {
        apiCallMatches.forEach(match => {
          const parts = match.match(/(\w+)\s*\.\s*(\w+)\s*\(/);
          if (parts) {
            const [_, obj, method] = parts;
            if (obj && method && !KNOWN_GLOBAL_APIS.has(obj)) {
              elements.push({
                type: 'UNKNOWN_API',
                name: `${obj}.${method}`,
                file: filePath,
                line: index + 1,
                snippet: line.trim(),
                context: this.getContext(lines, index)
              });
            }
          }
        });
      }

      const functionCalls = line.match(/(\w+)\s*\(/g);
      if (functionCalls) {
        functionCalls.forEach(match => {
          const funcName = match.match(/(\w+)\s*\(/)?.[1];
          if (funcName && !this.isKnownFunction(funcName) && !this.isStandardLibrary(funcName)) {
            elements.push({
              type: 'UNKNOWN_FUNCTION',
              name: funcName,
              file: filePath,
              line: index + 1,
              snippet: line.trim(),
              context: this.getContext(lines, index)
            });
          }
        });
      }

      if (line.includes('eval(') || line.includes('new Function(')) {
        elements.push({
          type: 'UNSUPPORTED_SECURITY_ASSUMPTION',
          name: line.includes('eval(') ? 'eval' : 'new Function',
          file: filePath,
          line: index + 1,
          snippet: line.trim(),
          context: this.getContext(lines, index)
        });
      }

      if (line.match(/process\.env\.\w+/) && !line.includes('process.env.NODE_ENV')) {
        elements.push({
          type: 'SUSPICIOUS_DEPENDENCY',
          name: line.match(/process\.env\.(\w+)/)?.[1] || 'unknown',
          file: filePath,
          line: index + 1,
          snippet: line.trim(),
          context: this.getContext(lines, index)
        });
      }
    });

    return elements;
  }

  async verifyElements(
    elements: ExtractedElement[],
    fileContent: string
  ): Promise<VerificationResult[]> {
    const results: VerificationResult[] = [];

    for (const element of elements) {
      const result = await this.verifyElement(element, fileContent);
      results.push(result);
    }

    return results;
  }

  private async verifyElement(
    element: ExtractedElement,
    fileContent: string
  ): Promise<VerificationResult> {
    const evidence: string[] = [];
    let status: VerificationStatus = 'NOT_VERIFIED';
    let confidence = 0.5;
    const details: Record<string, any> = {};

    switch (element.type) {
      case 'NON_EXISTENT_PACKAGE':
      case 'SUSPICIOUS_IMPORT':
        const npmResult = await this.verifyNpmPackage(element.name);
        if (npmResult.exists) {
          status = 'CONFIRMED';
          confidence = 0.95;
          evidence.push(`Package '${element.name}' exists on npm registry`);
          details.package_info = npmResult;
        } else {
          const isSuspicious = this.isSuspiciousPackageName(element.name);
          if (isSuspicious) {
            status = 'LIKELY';
            confidence = 0.8;
            evidence.push(`Package '${element.name}' not found on npm`);
            evidence.push('Package name contains suspicious patterns');
          } else {
            status = 'SUSPICIOUS';
            confidence = 0.6;
            evidence.push(`Package '${element.name}' not found on npm`);
          }
        }
        break;

      case 'UNKNOWN_API':
        const apiKnown = this.isKnownApi(element.name);
        if (apiKnown) {
          status = 'CONFIRMED';
          confidence = 0.9;
          evidence.push(`API '${element.name}' is a known API`);
        } else {
          const isSuspiciousApi = this.isSuspiciousApiUsage(element.name, fileContent);
          if (isSuspiciousApi) {
            status = 'LIKELY';
            confidence = 0.75;
            evidence.push(`API '${element.name}' usage appears suspicious`);
          } else {
            status = 'SUSPICIOUS';
            confidence = 0.5;
            evidence.push(`API '${element.name}' not recognized as standard`);
          }
        }
        break;

      case 'UNKNOWN_FUNCTION':
        const funcKnown = this.isKnownFunction(element.name);
        if (funcKnown) {
          status = 'CONFIRMED';
          confidence = 0.9;
          evidence.push(`Function '${element.name}' is a known function`);
        } else {
          const funcDefined = this.isFunctionDefined(element.name, fileContent);
          if (funcDefined) {
            status = 'CONFIRMED';
            confidence = 0.85;
            evidence.push(`Function '${element.name}' is defined in the codebase`);
          } else {
            status = 'SUSPICIOUS';
            confidence = 0.6;
            evidence.push(`Function '${element.name}' not found in known APIs or local definitions`);
          }
        }
        break;

      case 'INCORRECT_API_USAGE':
        const usageCorrect = this.verifyApiUsage(element.name, fileContent);
        if (usageCorrect) {
          status = 'CONFIRMED';
          confidence = 0.9;
          evidence.push(`API '${element.name}' usage appears correct`);
        } else {
          status = 'LIKELY';
          confidence = 0.7;
          evidence.push(`API '${element.name}' usage may be incorrect`);
        }
        break;

      case 'UNSUPPORTED_SECURITY_ASSUMPTION':
        status = 'LIKELY';
        confidence = 0.85;
        evidence.push('Code contains potentially unsafe patterns');
        details.security_concern = element.name;
        break;

      case 'SUSPICIOUS_DEPENDENCY':
        const envVar = element.name;
        const envUsed = fileContent.includes(`process.env.${envVar}`);
        if (envUsed) {
          const envDefined = this.isEnvironmentVariableDefined(envVar);
          if (envDefined) {
            status = 'CONFIRMED';
            confidence = 0.9;
            evidence.push(`Environment variable '${envVar}' is properly defined`);
          } else {
            status = 'SUSPICIOUS';
            confidence = 0.65;
            evidence.push(`Environment variable '${envVar}' may not be defined`);
          }
        }
        break;
    }

    return {
      element,
      status,
      evidence,
      confidence,
      details
    };
  }

  private compileFindings(
    results: VerificationResult[],
    filePath: string
  ): HallucinationFinding[] {
    const findings: HallucinationFinding[] = [];

    for (const result of results) {
      if (result.status !== 'CONFIRMED' || result.confidence < 0.8) {
        const severity = this.calculateSeverity(result);
        const finding: HallucinationFinding = {
          finding_id: this.generateFindingId(),
          type: result.element.type,
          file: filePath,
          line: result.element.line,
          evidence: result.evidence,
          explanation: this.generateExplanation(result),
          severity,
          confidence: result.confidence,
          verification_method: this.getVerificationMethod(result),
          verification_status: result.status
        };
        findings.push(finding);
      }
    }

    return findings;
  }

  private async verifyNpmPackage(packageName: string): Promise<{ exists: boolean; info?: any }> {
    const cached = this.npmRegistryCache.get(packageName);
    if (cached && Date.now() - cached.timestamp < this.CACHE_TTL) {
      return { exists: cached.exists };
    }

    try {
      const response = await fetch(`https://registry.npmjs.org/${packageName}`, {
        method: 'HEAD',
        signal: AbortSignal.timeout(5000)
      });

      const exists = response.status === 200;
      this.npmRegistryCache.set(packageName, { exists, timestamp: Date.now() });
      return { exists };
    } catch {
      this.npmRegistryCache.set(packageName, { exists: false, timestamp: Date.now() });
      return { exists: false };
    }
  }

  private isSuspiciousPackageName(name: string): boolean {
    const suspiciousPatterns = [
      /^[a-z]+-[a-z]+-[a-z]+$/,  // too many hyphens
      /[0-9]{5,}/,  // many consecutive numbers
      /^.{50,}/,  // too long
      /test|mock|fake|dummy/i,  // test-related names
      /undefined|null|NaN/i  // programming terms
    ];

    return suspiciousPatterns.some(pattern => pattern.test(name));
  }

  private isKnownApi(name: string): boolean {
    const parts = name.split('.');
    return parts[0] !== undefined && (
      KNOWN_GLOBAL_APIS.has(parts[0]) ||
      KNOWN_NODE_APIS.has(parts[0])
    );
  }

  private isSuspiciousApiUsage(apiName: string, content: string): boolean {
    const suspiciousPatterns = [
      new RegExp(`${apiName.replace('.', '\\.')}\\s*\\(\\s*['"][^'"]*eval`, 'i'),
      new RegExp(`${apiName.replace('.', '\\.')}\\s*\\(\\s*process\\.exit`, 'i'),
      new RegExp(`${apiName.replace('.', '\\.')}\\s*\\(\\s*require`, 'i')
    ];

    return suspiciousPatterns.some(pattern => pattern.test(content));
  }

  private isKnownFunction(name: string): boolean {
    const knownFunctions = new Set([
      'require', 'import', 'export', 'console', 'log', 'error', 'warn',
      'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval',
      'fetch', 'parseInt', 'parseFloat', 'isNaN', 'isFinite',
      'encodeURIComponent', 'decodeURIComponent', 'encodeURI', 'decodeURI',
      'JSON.parse', 'JSON.stringify', 'Object.keys', 'Object.values',
      'Array.isArray', 'Array.from', 'Math.floor', 'Math.ceil', 'Math.round',
      'Date.now', 'Promise.all', 'Promise.race', 'Promise.resolve', 'Promise.reject'
    ]);

    return knownFunctions.has(name);
  }

  private isStandardLibrary(name: string): boolean {
    return KNOWN_NODE_APIS.has(name) || name.startsWith('fs.') || name.startsWith('path.');
  }

  private isFunctionDefined(name: string, content: string): boolean {
    const functionPatterns = [
      new RegExp(`function\\s+${name}\\s*\\(`),
      new RegExp(`const\\s+${name}\\s*=\\s*(async\\s+)?\\(`),
      new RegExp(`let\\s+${name}\\s*=\\s*(async\\s+)?\\(`),
      new RegExp(`var\\s+${name}\\s*=\\s*(async\\s+)?\\(`),
      new RegExp(`${name}\\s*:\\s*function`),
      new RegExp(`${name}\\s*:\\s*(async\\s+)?\\(`)
    ];

    return functionPatterns.some(pattern => pattern.test(content));
  }

  private verifyApiUsage(apiName: string, content: string): boolean {
    const usagePattern = new RegExp(`${apiName.replace('.', '\\.')}\\s*\\(`);
    return usagePattern.test(content);
  }

  private isEnvironmentVariableDefined(varName: string): boolean {
    const envFiles = ['.env', '.env.local', '.env.development', '.env.production'];
    for (const envFile of envFiles) {
      if (fs.existsSync(envFile)) {
        const content = fs.readFileSync(envFile, 'utf-8');
        if (content.includes(`${varName}=`)) {
          return true;
        }
      }
    }
    return false;
  }

  private calculateSeverity(result: VerificationResult): SeverityLevel {
    if (result.confidence > 0.8 && result.status === 'LIKELY') {
      return 'HIGH';
    } else if (result.confidence > 0.6) {
      return 'MEDIUM';
    } else {
      return 'LOW';
    }
  }

  private generateExplanation(result: VerificationResult): string {
    const { element, status, evidence } = result;
    const evidenceStr = evidence.join('; ');

    switch (status) {
      case 'CONFIRMED':
        return `${element.type} '${element.name}' is verified as legitimate. Evidence: ${evidenceStr}`;
      case 'LIKELY':
        return `${element.type} '${element.name}' appears to be a potential hallucination. Evidence: ${evidenceStr}`;
      case 'SUSPICIOUS':
        return `${element.type} '${element.name}' shows suspicious characteristics. Evidence: ${evidenceStr}`;
      default:
        return `${element.type} '${element.name}' could not be fully verified. Evidence: ${evidenceStr}`;
    }
  }

  private getVerificationMethod(result: VerificationResult): string {
    switch (result.element.type) {
      case 'NON_EXISTENT_PACKAGE':
      case 'SUSPICIOUS_IMPORT':
        return 'NPM_REGISTRY_CHECK';
      case 'UNKNOWN_API':
      case 'UNKNOWN_FUNCTION':
        return 'KNOWN_API_DATABASE';
      case 'INCORRECT_API_USAGE':
        return 'USAGE_PATTERN_ANALYSIS';
      case 'UNSUPPORTED_SECURITY_ASSUMPTION':
        return 'SECURITY_PATTERN_SCAN';
      case 'SUSPICIOUS_DEPENDENCY':
        return 'ENVIRONMENT_VARIABLE_CHECK';
      default:
        return 'PATTERN_MATCHING';
    }
  }

  private getContext(lines: string[], currentIndex: number): string {
    const start = Math.max(0, currentIndex - 2);
    const end = Math.min(lines.length - 1, currentIndex + 2);
    return lines.slice(start, end + 1).join('\n');
  }

  private generateFindingId(): string {
    return `finding_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  async analyzeWithLLM(
    findings: HallucinationFinding[],
    fileContent: string
  ): Promise<LLMAnalysisResponse> {
    const request: LLMAnalysisRequest = {
      elements: findings.map(f => ({
        type: f.type,
        name: f.file,
        file: f.file,
        line: f.line,
        snippet: '',
        context: ''
      })),
      verification_results: findings.map(f => ({
        element: {
          type: f.type,
          name: f.file,
          file: f.file,
          line: f.line,
          snippet: '',
          context: ''
        },
        status: f.verification_status,
        evidence: f.evidence,
        confidence: f.confidence,
        details: {}
      })),
      file_content: fileContent
    };

    return {
      findings,
      reasoning: `Analyzed ${findings.length} potential hallucinations using multi-stage verification pipeline.`,
      metadata: {
        analysis_timestamp: new Date().toISOString(),
        total_findings: findings.length,
        verification_methods_used: [...new Set(findings.map(f => f.verification_method))]
      }
    };
  }
}

export const hallucinationDetectionService = new HallucinationDetectionService();
