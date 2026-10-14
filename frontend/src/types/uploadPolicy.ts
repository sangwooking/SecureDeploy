export interface UploadPolicy {
  maxZipBytes: number;
  maxZipLabel: string;
  maxRequestBytes: number;
  maxExpandedBytes: number;
  maxArchiveEntries: number;
  ignoredDirectories: string[];
  folderHint: string;
}
