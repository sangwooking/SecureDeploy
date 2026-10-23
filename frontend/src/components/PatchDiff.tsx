export function PatchDiff({ patch }: { patch: string }) {
  const lines=patch.split('\n');
  return <pre className="patch-diff" tabIndex={0} aria-label="변경 전후 코드 Diff">{lines.map((line, index) =>
    <span key={index} className={line.startsWith('@@') ? 'diff-hunk' : line.startsWith('+') && !line.startsWith('+++') ? 'diff-added' : line.startsWith('-') && !line.startsWith('---') ? 'diff-removed' : undefined}>{line}{index<lines.length-1?'\n':''}</span>)}
  </pre>;
}
