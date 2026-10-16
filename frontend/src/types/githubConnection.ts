export interface GitHubConnection {
  configured: boolean;
  connected: boolean;
  reconnectRequired: boolean;
  login: string | null;
  expiresAt: string | null;
  installationUrl: string | null;
}
export interface GitHubInstallation { installationId: number; account: string }
export interface ConnectedRepository {
  repositoryId: number;
  installationId: number;
  name: string;
  fullName: string;
  repositoryUrl: string;
  privateRepository: boolean;
  defaultBranch: string;
}
