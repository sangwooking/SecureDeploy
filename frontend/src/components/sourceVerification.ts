import type {EditingWorkspace} from '../api/editingApi';
/** Commit identity alone does not attest the bytes consumed by the saved analysis. */
export const originalVerified=(workspace:EditingWorkspace|null|undefined)=>workspace?.sourceVerification?.status==='VERIFIED';
