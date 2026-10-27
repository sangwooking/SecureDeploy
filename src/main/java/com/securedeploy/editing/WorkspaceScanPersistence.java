package com.securedeploy.editing;

import com.securedeploy.auth.service.ReviewAccessService;
import com.securedeploy.auth.service.ProjectOwnership;
import com.securedeploy.persistence.entity.ProjectEntity;
import com.securedeploy.persistence.repository.ProjectRepository;
import com.securedeploy.persistence.repository.UserRepository;
import com.securedeploy.review.model.ReviewSourceType;
import com.securedeploy.review.dto.SecurityReviewResponse;
import com.securedeploy.review.service.SecurityReviewFacade;
import com.securedeploy.project.service.ProjectLifecycleGuard;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class WorkspaceScanPersistence {
    private final ReviewAccessService access;
    private final ProjectRepository projects;
    private final UserRepository users;
    private final SecurityReviewFacade facade;
    private final ProjectLifecycleGuard lifecycle;
    public WorkspaceScanPersistence(ReviewAccessService access, ProjectRepository projects, UserRepository users,
            SecurityReviewFacade facade) {
        this(access, projects, users, facade, new ProjectLifecycleGuard());
    }
    @org.springframework.beans.factory.annotation.Autowired
    public WorkspaceScanPersistence(ReviewAccessService access, ProjectRepository projects, UserRepository users,
            SecurityReviewFacade facade, ProjectLifecycleGuard lifecycle) {
        this.access = access; this.projects = projects; this.users = users; this.facade = facade;
        this.lifecycle = lifecycle == null ? new ProjectLifecycleGuard() : lifecycle;
    }
    @Transactional
    public SecurityReviewResponse save(EditingWorkspaceService.ScanInput input,
            SecurityReviewFacade.AnalysisOutcome outcome, Runnable guard) {
        guard.run();
        var original = access.findAccessibleReviewWithVulnerabilities(input.provenance().originalReviewId(), "분석 결과에 접근할 수 없습니다.");
        ProjectOwnership.requireOwner(original.getProject(), input.userId());
        try (var lease = lifecycle.work(original.getProject().getId())) {
            access.findAccessibleReviewWithVulnerabilities(input.provenance().originalReviewId(), "분석 결과에 접근할 수 없습니다.");
            var project = original.getProject();
            if (!input.provenance().baselineVerified()) {
                project = new ProjectEntity(input.name() + " (수정본 " + java.util.UUID.randomUUID().toString().substring(0,8) + ")", ReviewSourceType.ZIP, null);
                project.assignUser(users.findById(input.userId()).orElseThrow());
                project = projects.save(project);
            }
            var result = facade.saveWorkspace(project, outcome, input.provenance());
            guard.run(); // A timed-out result must roll back, including a newly created ZIP baseline project.
            return result;
        }
    }
}
