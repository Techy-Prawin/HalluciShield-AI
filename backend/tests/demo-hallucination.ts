import { HallucinationDetectionService } from '../src/services/hallucinationDetection.service';

async function runDemo() {
  const service = new HallucinationDetectionService();

  console.log('=== Hallucination Detection Demo ===\n');

  const testFiles = [
    {
      path: 'valid-app.ts',
      content: `
import express from 'express';
import cors from 'cors';
import { Pool } from 'pg';

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

app.use(cors());

app.get('/api/health', async (req, res) => {
  const result = await pool.query('SELECT 1');
  res.json({ status: 'ok', db: result.rows.length > 0 });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
      `
    },
    {
      path: 'hallucinated-code.ts',
      content: `
import express from 'express';
import fakePackage from 'completely-fake-package-xyz';
import { FakeComponent } from 'non-existent-ui-library';

const app = express();
const fake = fakePackage.initialize();

// Suspicious function call
unknownHelper();
suspiciousFunction(data);

// Security concern
eval(userInput);
const fn = new Function('return ' + code);

// Unknown API usage
const result = fakeApi.nonExistentMethod(data);
const value = anotherFakeLib.getValue();

// Environment variable usage
const apiKey = process.env.UNDEFINED_API_KEY;
const secret = process.env.MISSING_SECRET;

console.log(fake, result, value);
      `
    }
  ];

  console.log('--- Test File 1: Valid Application Code ---');
  console.log('Analyzing:', testFiles[0].path);
  
  const findings1 = await service.detectHallucinations([testFiles[0]]);
  console.log(`Findings: ${findings1.length}`);
  
  if (findings1.length > 0) {
    findings1.forEach(f => {
      console.log(`\n  Finding: ${f.finding_id}`);
      console.log(`  Type: ${f.type}`);
      console.log(`  Severity: ${f.severity}`);
      console.log(`  Confidence: ${f.confidence}`);
      console.log(`  Status: ${f.verification_status}`);
      console.log(`  Evidence: ${f.evidence.join(', ')}`);
    });
  } else {
    console.log('  No hallucinations detected - code appears valid!');
  }

  console.log('\n\n--- Test File 2: Hallucinated Code ---');
  console.log('Analyzing:', testFiles[1].path);
  
  const findings2 = await service.detectHallucinations([testFiles[1]]);
  console.log(`Findings: ${findings2.length}`);
  
  findings2.forEach(f => {
    console.log(`\n  Finding: ${f.finding_id}`);
    console.log(`  Type: ${f.type}`);
    console.log(`  File: ${f.file}`);
    console.log(`  Line: ${f.line}`);
    console.log(`  Severity: ${f.severity}`);
    console.log(`  Confidence: ${f.confidence}`);
    console.log(`  Status: ${f.verification_status}`);
    console.log(`  Evidence:`);
    f.evidence.forEach(e => console.log(`    - ${e}`));
    console.log(`  Explanation: ${f.explanation}`);
  });

  console.log('\n\n--- LLM Analysis Response ---');
  const analysis = await service.analyzeWithLLM(findings2, testFiles[1].content);
  console.log('Analysis Metadata:', JSON.stringify(analysis.metadata, null, 2));

  console.log('\n=== Demo Complete ===');
}

runDemo().catch(console.error);
