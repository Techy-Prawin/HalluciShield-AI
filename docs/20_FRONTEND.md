# 20 - Frontend

## Overview

Next.js 14 dashboard providing repository upload, scan initiation, and result visualization.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Framework | Next.js 14.2 |
| UI Library | React 18.3 |
| Language | TypeScript 5.6 |
| Charts | Recharts 3.10 |
| CSS | CSS Modules |
| Testing | Vitest + @testing-library/react |

## Pages

### Home (`/`)

Main dashboard with:
- Repository upload portal
- Recent scans list
- System status indicators

### Components

#### UploadPortal

Drag-and-drop repository upload:
- Accepts `.zip` files up to 50MB
- Upload progress tracking
- Repository metadata display
- Scan initiation button

```tsx
<UploadPortal onScanRequested={(repoId) => startScan(repoId)} />
```

#### ExperimentAnalytics

Charts and metrics visualization:
- Scan history timeline
- Vulnerability distribution
- Confidence score trends

## API Communication

Frontend communicates with backend via `NEXT_PUBLIC_API_URL` (default: `http://localhost:4000`).

### Upload Flow

```typescript
const xhr = new XMLHttpRequest();
xhr.open('POST', `${backendUrl}/api/repositories/upload`);
xhr.upload.onprogress = (e) => setProgress(e.loaded / e.total * 100);
xhr.onload = () => handleResponse(JSON.parse(xhr.responseText));
xhr.send(formData);
```

## Docker

Multi-stage build:
1. **Builder**: `npm ci` + `npm run build`
2. **Runner**: Copies `.next/standalone`, runs `node server.js`

Port: 3000

## File Structure

```
frontend/
├── app/
│   ├── layout.tsx            # Root layout
│   ├── page.tsx              # Home page
│   └── components/
│       ├── UploadPortal.tsx  # Upload component
│       └── ExperimentAnalytics.tsx  # Analytics
├── public/                   # Static assets
├── Dockerfile                # Multi-stage build
└── package.json
```
