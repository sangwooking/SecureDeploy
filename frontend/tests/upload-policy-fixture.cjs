module.exports = {
  maxZipBytes: 200 * 1024 * 1024, maxZipLabel: '200MB', maxRequestBytes: 205 * 1024 * 1024,
  maxExpandedBytes: 1024 * 1024 * 1024, maxArchiveEntries: 50000,
  ignoredDirectories: ['node_modules', '.git', 'build', 'dist', 'target', 'out', '.gradle', 'coverage', 'vendor'],
  folderHint: 'node_modules, .git, build, dist, target 등 생성 파일이나 외부 라이브러리 폴더를 제외한 뒤 다시 압축해 주세요.',
};
