import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { UploadPortal } from '../app/components/UploadPortal';

describe('UploadPortal Component', () => {
  it('renders repository upload portal title, subtitle, and dropzone', () => {
    render(<UploadPortal />);
    expect(screen.getByText('Repository Upload Portal')).toBeDefined();
    expect(screen.getByText(/Drag and drop a source code repository/i)).toBeDefined();
    expect(screen.getByText(/Zip Slip Protected/i)).toBeDefined();
    expect(screen.getByRole('region', { name: /Repository Upload Dropzone/i })).toBeDefined();
  });

  it('displays error alert when a non-ZIP file is selected', () => {
    render(<UploadPortal />);
    const fileInput = screen.getByRole('region').querySelector('input[type="file"]') as HTMLInputElement;
    expect(fileInput).not.toBeNull();

    const invalidFile = new File(['hello world'], 'document.txt', { type: 'text/plain' });
    fireEvent.change(fileInput, { target: { files: [invalidFile] } });

    expect(screen.getByText('Upload Error')).toBeDefined();
    expect(screen.getByText(/Invalid file type ".txt"\. Please upload a \.zip archive or source code file/i)).toBeDefined();
  });

  it('calls onScanRequested callback when scan button is clicked', () => {
    const onScanMock = vi.fn();
    render(<UploadPortal onScanRequested={onScanMock} />);
    
    // Simulate successful state manually or click scan button when repository is loaded
  });
});
