interface DangerousPreviewProps {
  html: string;
}

export default function DangerousPreview({ html }: DangerousPreviewProps) {
  return <section dangerouslySetInnerHTML={{ __html: html }} />;
}
