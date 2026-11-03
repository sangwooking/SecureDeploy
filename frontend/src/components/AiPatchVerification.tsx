import type { AiPatch } from '../api/editingApi';

export function AiPatchVerification({selected, deterministic}: {selected: AiPatch; deterministic: boolean}) {
  return <>
      {deterministic || !['PROPOSED','ACCEPTED','NEEDS_REVIEW'].includes(selected.state)
        ? <p>{selected.explanation}</p>
        : <details><summary>{selected.provider.origin==='MOCK'?'Mock 설명':'AI 수정 조언'} · 사실 여부 미검증</summary>
            <p>{selected.explanation}</p>
            {selected.verificationSteps.length > 0 && <><h4>수정 후 확인할 항목</h4><ul>{selected.verificationSteps.map((s,i) => <li key={i}>{s}</li>)}</ul></>}
            {selected.limitations.length > 0 && <><h4>잠재적 영향과 한계</h4><ul>{selected.limitations.map((s,i) => <li key={i}>{s}</li>)}</ul></>}
          </details>}
      {selected.diff && <section aria-label="서버 변경 검증 결과">
        <h4>서버 변경 검증</h4>
        <p>대상 파일과 원본 해시, 작업 공간 Revision, 허용된 변경 범위를 확인했습니다.</p>
        {selected.plan && selected.context && <p>AST 검사에서 제거 대상 {selected.context.removedFields.join(', ')} 및 보존 대상 {selected.context.preservedFields.join(', ')}을 확인했습니다.</p>}
        <p>AI 설명의 사실 여부, 실제 실행 동작과 API 호환성은 이 검사에 포함되지 않습니다. 적용 후 재검사 결과는 검사 기록에서 확인하세요.</p>
      </section>}
  </>;
}
