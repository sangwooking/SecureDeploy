package com.securedeploy.threatintel.model;

import java.time.Instant;
import java.time.LocalDate;

public record EpssData(String cve, Double score, Double percentile, LocalDate date,
                       LookupStatus status, String source, Instant fetchedAt) {
    public EpssData withStatus(LookupStatus value) {
        return new EpssData(cve, score, percentile, date, value, source, fetchedAt);
    }
}
