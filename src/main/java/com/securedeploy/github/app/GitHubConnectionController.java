package com.securedeploy.github.app;

import com.securedeploy.auth.service.CurrentUserService;
import com.securedeploy.global.dto.DeleteResponse;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/github")
public class GitHubConnectionController {
    private final CurrentUserService users;
    private final GitHubConnectionService connections;
    public GitHubConnectionController(CurrentUserService users, GitHubConnectionService connections) {
        this.users = users; this.connections = connections;
    }
    @GetMapping("/connection")
    public GitHubAppDtos.ConnectionStatus status() { return connections.status(users.currentUserId()); }
    @PostMapping("/connection/authorize")
    public GitHubAppDtos.Authorization begin(@RequestHeader("Authorization") String session) { return connections.begin(users.currentUserId(), session); }
    @PostMapping("/connection/callback")
    public GitHubAppDtos.ConnectionStatus callback(@RequestHeader("Authorization") String session, @Valid @RequestBody GitHubAppDtos.Callback callback) {
        return connections.complete(users.currentUserId(), session, callback);
    }
    @DeleteMapping("/connection")
    public DeleteResponse disconnect() { return new DeleteResponse(connections.disconnect(users.currentUserId())); }
    @GetMapping("/installations")
    public GitHubAppDtos.InstallationPage installations(@RequestParam(defaultValue = "1") int page) { return connections.installations(users.currentUserId(), page); }
    @GetMapping("/installations/{installationId}/repositories")
    public GitHubAppDtos.RepositoryPage repositories(@PathVariable long installationId, @RequestParam(defaultValue = "1") int page) {
        return connections.repositories(users.currentUserId(), installationId, page);
    }
}
