package com.securedeploy.threatintel.model;

import java.time.Instant;
import java.time.LocalDate;

public record KevData(String cve, Boolean knownExploited, LocalDate dateAdded,
                      String requiredAction, LocalDate dueDate, String knownRansomwareCampaignUse,
                      String catalogVersion, Instant catalogReleasedAt, LookupStatus status,
                      String source, Instant fetchedAt) { }
