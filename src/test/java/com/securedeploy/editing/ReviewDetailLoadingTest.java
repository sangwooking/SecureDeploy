package com.securedeploy.editing;
import static org.junit.jupiter.api.Assertions.*;
import com.securedeploy.persistence.entity.*;
import com.securedeploy.persistence.repository.ReviewRepository;
import com.securedeploy.review.model.ReviewSourceType;
import com.securedeploy.rule.model.*;
import jakarta.persistence.EntityManager;
import org.hibernate.Hibernate;
import org.hibernate.SessionFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
/** Prevent large parent JSON from being duplicated once per Finding by a fetch join. */
@DataJpaTest(properties="spring.jpa.properties.hibernate.generate_statistics=true")
class ReviewDetailLoadingTest {
 @Autowired ReviewRepository reviews;@Autowired EntityManager em;
 @Test void separateCollectionLoadRetainsAllFindingsAndDetachedReadContract(){
  var r=new ReviewEntity("synthetic-many-findings",ReviewSourceType.ZIP,null,1,200,0,"READY_WITH_WARNINGS");
  for(int i=0;i<200;i++)r.addVulnerability(new VulnerabilityEntity("DEBUG_ENABLED",RuleCategory.CONFIGURATION,Severity.MEDIUM,"src/a.properties",i+1,"synthetic title","manual check","debug=true"));
  r=reviews.saveAndFlush(r);long id=r.getId();em.clear();
  var stats=em.getEntityManagerFactory().unwrap(SessionFactory.class).getStatistics();stats.clear();
  var loaded=reviews.findByIdWithVulnerabilities(id).orElseThrow();assertTrue(Hibernate.isInitialized(loaded.getVulnerabilities()));
  assertTrue(stats.getPrepareStatementCount()>=2,"parent and collection must be selected separately");
  assertTrue(stats.getPrepareStatementCount()<=5,"avoid one query per Finding");
  em.detach(loaded);assertEquals(200,loaded.getVulnerabilities().size());assertEquals(200,loaded.getVulnerabilityCount());
  assertEquals(200,loaded.getVulnerabilities().stream().map(VulnerabilityEntity::getLine).distinct().count());
 }
}
