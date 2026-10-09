package com.securedeploy.threatintel.model;

public record ThreatIntelligence(String cve, EpssData epss, KevData kev) { }
