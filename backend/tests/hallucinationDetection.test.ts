import { HallucinationDetectionService } from '../src/services/hallucinationDetection.service';

describe('HallucinationDetectionService', () => {
  let service: HallucinationDetectionService;

  beforeEach(() => {
    service = new HallucinationDetectionService();
  });

  describe('extractSuspiciousElements', () => {
    it('should extract import statements', () => {
      const content = `
        import express from 'express';
        import { useState } from 'react';
        const axios = require('axios');
      `;
      const elements = service.extractSuspiciousElements(content, 'test.ts');

      expect(elements.length).toBeGreaterThanOrEqual(3);
      const imports = elements.filter(e => e.type === 'SUSPICIOUS_IMPORT');
      expect(imports.length).toBeGreaterThanOrEqual(3);
      expect(imports.map(e => e.name)).toContain('express');
      expect(imports.map(e => e.name)).toContain('react');
      expect(imports.map(e => e.name)).toContain('axios');
    });

    it('should extract unknown API calls', () => {
      const content = `
        const result = unknownLibrary.someMethod(data);
        const value = customApi.getValue();
      `;
      const elements = service.extractSuspiciousElements(content, 'test.ts');

      const apis = elements.filter(e => e.type === 'UNKNOWN_API');
      expect(apis.length).toBeGreaterThanOrEqual(2);
    });

    it('should extract eval usage as security concern', () => {
      const content = `
        eval(userInput);
        const fn = new Function('return ' + code);
      `;
      const elements = service.extractSuspiciousElements(content, 'test.ts');

      const security = elements.filter(e => e.type === 'UNSUPPORTED_SECURITY_ASSUMPTION');
      expect(security.length).toBe(2);
    });

    it('should extract environment variable usage', () => {
      const content = `
        const dbUrl = process.env.DATABASE_URL;
        const apiKey = process.env.API_KEY;
      `;
      const elements = service.extractSuspiciousElements(content, 'test.ts');

      const deps = elements.filter(e => e.type === 'SUSPICIOUS_DEPENDENCY');
      expect(deps.length).toBe(2);
      expect(deps.map(e => e.name)).toContain('DATABASE_URL');
      expect(deps.map(e => e.name)).toContain('API_KEY');
    });

    it('should handle empty content gracefully', () => {
      const elements = service.extractSuspiciousElements('', 'test.ts');
      expect(elements).toEqual([]);
    });
  });

  describe('verifyElements', () => {
    it('should verify known packages as CONFIRMED', async () => {
      const elements = [
        {
          type: 'SUSPICIOUS_IMPORT' as const,
          name: 'express',
          file: 'test.ts',
          line: 1,
          snippet: "import express from 'express';",
          context: ''
        }
      ];

      const results = await service.verifyElements(elements, '');
      expect(results.length).toBe(1);
      expect(results[0].status).toBe('CONFIRMED');
      expect(results[0].confidence).toBeGreaterThanOrEqual(0.9);
    });

    it('should flag non-existent packages as LIKELY or SUSPICIOUS', async () => {
      const elements = [
        {
          type: 'SUSPICIOUS_IMPORT' as const,
          name: 'fake-nonexistent-package-xyz123',
          file: 'test.ts',
          line: 1,
          snippet: "import fake from 'fake-nonexistent-package-xyz123';",
          context: ''
        }
      ];

      const results = await service.verifyElements(elements, '');
      expect(results.length).toBe(1);
      expect(['LIKELY', 'SUSPICIOUS']).toContain(results[0].status);
      expect(results[0].evidence.length).toBeGreaterThan(0);
    });

    it('should verify known global APIs', async () => {
      const elements = [
        {
          type: 'UNKNOWN_API' as const,
          name: 'console.log',
          file: 'test.ts',
          line: 1,
          snippet: 'console.log("hello");',
          context: ''
        }
      ];

      const results = await service.verifyElements(elements, '');
      expect(results.length).toBe(1);
      expect(results[0].status).toBe('CONFIRMED');
    });

    it('should verify functions defined in codebase', async () => {
      const content = `
        function customHelper() {
          return 42;
        }
        customHelper();
      `;
      const elements = [
        {
          type: 'UNKNOWN_FUNCTION' as const,
          name: 'customHelper',
          file: 'test.ts',
          line: 5,
          snippet: 'customHelper();',
          context: ''
        }
      ];

      const results = await service.verifyElements(elements, content);
      expect(results.length).toBe(1);
      expect(results[0].status).toBe('CONFIRMED');
    });

    it('should flag security concerns appropriately', async () => {
      const elements = [
        {
          type: 'UNSUPPORTED_SECURITY_ASSUMPTION' as const,
          name: 'eval',
          file: 'test.ts',
          line: 1,
          snippet: 'eval(userInput);',
          context: ''
        }
      ];

      const results = await service.verifyElements(elements, '');
      expect(results.length).toBe(1);
      expect(results[0].status).toBe('LIKELY');
      expect(results[0].confidence).toBeGreaterThanOrEqual(0.8);
    });
  });

  describe('detectHallucinations', () => {
    it('should detect hallucinations in valid code with known packages', async () => {
      const files = [
        {
          path: 'app.ts',
          content: `
            import express from 'express';
            import cors from 'cors';

            const app = express();
            app.use(cors());

            app.get('/', (req, res) => {
              res.json({ status: 'ok' });
            });

            app.listen(3000);
          `
        }
      ];

      const findings = await service.detectHallucinations(files);
      expect(Array.isArray(findings)).toBe(true);
    });

    it('should detect fake packages', async () => {
      const files = [
        {
          path: 'app.ts',
          content: `
            import fakePackage from 'completely-fake-package-12345';
            console.log(fakePackage);
          `
        }
      ];

      const findings = await service.detectHallucinations(files);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings.some(f => f.type === 'SUSPICIOUS_IMPORT')).toBe(true);
    });

    it('should detect fake APIs', async () => {
      const files = [
        {
          path: 'api.ts',
          content: `
            const result = fakeLibrary.nonExistentMethod(data);
            const value = anotherFakeApi.getValue();
          `
        }
      ];

      const findings = await service.detectHallucinations(files);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect suspicious functions', async () => {
      const files = [
        {
          path: 'utils.ts',
          content: `
            suspiciousFunction();
            unknownHelper();
          `
        }
      ];

      const findings = await service.detectHallucinations(files);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should handle valid API with unusual usage', async () => {
      const files = [
        {
          path: 'test.ts',
          content: `
            const data = JSON.parse(invalidJson);
            console.log(data);
          `
        }
      ];

      const findings = await service.detectHallucinations(files);
      expect(Array.isArray(findings)).toBe(true);
    });
  });

  describe('analyzeWithLLM', () => {
    it('should return structured analysis response', async () => {
      const findings = [
        {
          finding_id: 'test_1',
          type: 'SUSPICIOUS_IMPORT' as const,
          file: 'test.ts',
          line: 1,
          evidence: ['Package not found on npm'],
          explanation: 'Test explanation',
          severity: 'MEDIUM' as const,
          confidence: 0.7,
          verification_method: 'NPM_REGISTRY_CHECK',
          verification_status: 'SUSPICIOUS' as const
        }
      ];

      const result = await service.analyzeWithLLM(findings, 'test content');
      expect(result).toHaveProperty('findings');
      expect(result).toHaveProperty('reasoning');
      expect(result).toHaveProperty('metadata');
      expect(result.findings).toEqual(findings);
      expect(typeof result.reasoning).toBe('string');
    });
  });

  describe('finding structure', () => {
    it('should return findings with all required fields', async () => {
      const files = [
        {
          path: 'test.ts',
          content: `
            import fakePkg from 'fake-package';
            console.log(fakePkg);
          `
        }
      ];

      const findings = await service.detectHallucinations(files);

      if (findings.length > 0) {
        const finding = findings[0];
        expect(finding).toHaveProperty('finding_id');
        expect(finding).toHaveProperty('type');
        expect(finding).toHaveProperty('file');
        expect(finding).toHaveProperty('line');
        expect(finding).toHaveProperty('evidence');
        expect(finding).toHaveProperty('explanation');
        expect(finding).toHaveProperty('severity');
        expect(finding).toHaveProperty('confidence');
        expect(finding).toHaveProperty('verification_method');
        expect(finding).toHaveProperty('verification_status');

        expect(typeof finding.finding_id).toBe('string');
        expect(typeof finding.type).toBe('string');
        expect(typeof finding.file).toBe('string');
        expect(typeof finding.line).toBe('number');
        expect(Array.isArray(finding.evidence)).toBe(true);
        expect(typeof finding.explanation).toBe('string');
        expect(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(finding.severity);
        expect(typeof finding.confidence).toBe('number');
        expect(finding.confidence).toBeGreaterThanOrEqual(0);
        expect(finding.confidence).toBeLessThanOrEqual(1);
        expect(['CONFIRMED', 'LIKELY', 'SUSPICIOUS', 'NOT_VERIFIED']).toContain(finding.verification_status);
      }
    });
  });

  describe('severity and confidence', () => {
    it('should assign appropriate severity based on confidence', async () => {
      const files = [
        {
          path: 'test.ts',
          content: `
            import verySuspiciousPackage12345 from 'very-suspicious-package-12345';
            eval(verySuspiciousPackage12345);
          `
        }
      ];

      const findings = await service.detectHallucinations(files);
      findings.forEach(finding => {
        expect(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(finding.severity);
        expect(finding.confidence).toBeGreaterThanOrEqual(0);
        expect(finding.confidence).toBeLessThanOrEqual(1);
      });
    });
  });

  describe('verification status distribution', () => {
    it('should have valid verification statuses', async () => {
      const files = [
        {
          path: 'mixed.ts',
          content: `
            import express from 'express';
            import fakePkg from 'fake-package-xyz';
            console.log(fakePkg);
          `
        }
      ];

      const findings = await service.detectHallucinations(files);
      findings.forEach(finding => {
        expect(['CONFIRMED', 'LIKELY', 'SUSPICIOUS', 'NOT_VERIFIED']).toContain(finding.verification_status);
      });
    });
  });

  describe('multiple files analysis', () => {
    it('should analyze multiple files correctly', async () => {
      const files = [
        {
          path: 'file1.ts',
          content: `
            import express from 'express';
            console.log('file1');
          `
        },
        {
          path: 'file2.ts',
          content: `
            import fakePkg from 'fake-package';
            console.log(fakePkg);
          `
        }
      ];

      const findings = await service.detectHallucinations(files);
      expect(findings.length).toBeGreaterThan(0);
      const file1Findings = findings.filter(f => f.file === 'file1.ts');
      const file2Findings = findings.filter(f => f.file === 'file2.ts');
      expect(file1Findings.length).toBeGreaterThanOrEqual(0);
      expect(file2Findings.length).toBeGreaterThanOrEqual(0);
    });
  });
});
