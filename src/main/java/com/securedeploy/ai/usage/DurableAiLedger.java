package com.securedeploy.ai.usage;

import java.math.BigDecimal;
import java.time.*;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.stereotype.Component;

/** PostgreSQL admission gate shared by every real transport. Estimates are never invoices. */
@Component
public class DurableAiLedger {
    private final JdbcTemplate db;private final TransactionTemplate tx;private final boolean enabled;
    private final BigDecimal userLimit,projectLimit,serviceLimit;
    public DurableAiLedger(JdbcTemplate db,@Value("${securedeploy.ai.ledger.enabled:false}") boolean enabled,
            @Value("${securedeploy.ai.ledger.user-daily-usd:0.10}") BigDecimal userLimit,
            @Value("${securedeploy.ai.ledger.project-daily-usd:0.20}") BigDecimal projectLimit,
            @Value("${securedeploy.ai.ledger.service-daily-usd:1.00}") BigDecimal serviceLimit){
        this.db=db;this.enabled=enabled;this.userLimit=userLimit;this.projectLimit=projectLimit;this.serviceLimit=serviceLimit;
        tx=new TransactionTemplate(new DataSourceTransactionManager(Objects.requireNonNull(db.getDataSource())));
        tx.setPropagationBehavior(org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        if(enabled){if(userLimit.signum()<=0||projectLimit.signum()<=0||serviceLimit.signum()<=0)throw denied();
            db.queryForObject("select count(*) from ai_usage_request_v1 where 1=0",Long.class);
            if(db.queryForObject("select count(*) from ai_usage_gate_v1 where id=1",Long.class)!=1)throw denied();}
    }
    public static final class ExhibitLimit extends IllegalStateException {
        private final boolean budget;
        ExhibitLimit(boolean budget){this.budget=budget;}
        public boolean budget(){return budget;}
    }
    private ExhibitAiGate exhibit;
    @org.springframework.beans.factory.annotation.Autowired
    void configureExhibit(@Value("${securedeploy.ai.exhibit.control-file:}") String control,
            @Value("${securedeploy.ai.exhibit.express-scope:}") String express,
            @Value("${securedeploy.ai.exhibit.spring-scope:}") String spring,
            @Value("${spring.datasource.url:}") String datasource) {
        boolean persistent="jdbc:postgresql://127.0.0.1:58869/securedeploy_exhibit_live".equals(datasource);
        if (persistent && control.isBlank()) throw new IllegalStateException("Exhibition authorization path required");
        if (!control.isBlank()) {
            if (!enabled || (!persistent && !"jdbc:postgresql://127.0.0.1:58850/securedeploy_exhibit_step2".equals(datasource)))
                throw new IllegalStateException("Exhibition requires the dedicated local database");
            exhibit=new ExhibitAiGate(java.nio.file.Path.of(control),express,spring,persistent);
        }
    }
    @org.springframework.beans.factory.annotation.Autowired
    void configureMainCutover(
            @Value("${securedeploy.ai.main-cutover.control-file:}") String control,
            @Value("${securedeploy.ai.main-cutover.express-scope:}") String express,
            @Value("${securedeploy.ai.main-cutover.spring-scope:}") String spring,
            @Value("${securedeploy.ai.main-cutover.previous-request-id:}") String previous,
            @Value("${server.port:8080}") int port) {
        if(control.isBlank())return;
        if(!enabled || port!=8080 || exhibit!=null
                || !previous.matches("[A-Za-z0-9_-]{1,128}"))
            throw new IllegalStateException("Invalid main AI cutover configuration");
        var row=db.queryForObject("""
            select count(*) from ai_usage_request_v1
            where request_id=? and provider='OPENAI' and model='gpt-5.4-mini-2026-03-17'
            and state='COMPLETED' and reserved_usd=0.033576000
            """,Long.class,previous);
        if(row!=1)throw new IllegalStateException("Original AI reservation is missing");
        exhibit=new ExhibitAiGate(java.nio.file.Path.of(control),express,spring,true,ExhibitAiGate.MAIN_AUTHORIZATION);
    }
    public void requireTransmissionOpen(){if(!transmissionOpen())throw denied();}
    public boolean transmissionOpen(){return exhibit==null||exhibit.open();}
    public boolean enabled(){return enabled;}
    public String reserve(AiAdmission.Request r,String feature,String model,String wireHash,int input,int output){
        if(!Set.of("workspace_patch_v1","workspace_patch_plan_v1","dependency_update_advice_v1","semantic_review").contains(feature)||!enabled||r==null||r.user()<=0||r.project()<=0||!feature.equals(r.feature())||!model.equals(r.model())||!wireHash.equals(r.transmissionHash())
                ||!r.requestId().matches("[A-Za-z0-9_-]{1,128}")||!r.consentHash().matches("[0-9a-f]{64}")||input<1||input>32768||output<1||output>4000||!AiCostPolicy.priced(model))throw denied();
        if(exhibit!=null&&!exhibit.permits(r,AiAdmission.exhibitSource(),input,output))throw denied();
        BigDecimal reserved=AiCostPolicy.cost(new AiTokenUsage(input,output,input+output,true,0,model,true));
        // First durable event survives a later quota failure; duplicate IDs are never retransmitted.
        try{db.update("insert into ai_usage_request_v1(request_id,user_id,project_id,feature,provider,model,consent_hash,transmission_hash,state,reserved_input,reserved_output,reserved_usd) values(?,?,?,?,?,?,?,?, 'PREPARED',?,?,?)",
                r.requestId(),r.user(),r.project(),feature,"OPENAI",model,r.consentHash(),wireHash,input,output,reserved);}
        catch(org.springframework.dao.DataIntegrityViolationException duplicate){throw denied();}
        try{tx.executeWithoutResult(s->{
            db.queryForObject("select id from ai_usage_gate_v1 where id=1 for update",Integer.class);
            if(exhibit!=null){
                var exhibition=db.queryForMap("select count(*) as n,count(*) filter(where feature=?) as same,coalesce(sum(reserved_usd),0) as total from ai_usage_request_v1 where state not in ('PREPARED','PRE_SEND_FAILED')",feature);
                int count=((Number)exhibition.get("n")).intValue();
                var total=(BigDecimal)exhibition.get("total");
                if(exhibit.persistent() && count>=10)throw new ExhibitLimit(false);
                if(exhibit.persistent() && total.add(reserved).compareTo(new BigDecimal("0.50"))>0)throw new ExhibitLimit(true);
                if(!exhibit.permitsReservation(((Number)exhibition.get("n")).intValue(),
                        ((Number)exhibition.get("same")).intValue(),(BigDecimal)exhibition.get("total"),reserved))throw denied();
            }
            var rows=db.queryForList("select user_id,project_id,greatest(reserved_usd,coalesce(estimated_usd,0)) as reserved_usd,created_at,state,(created_at>current_timestamp-interval '1 hour') as hourly from ai_usage_request_v1 where created_at>current_timestamp-interval '24 hours' and state not in ('PREPARED','PRE_SEND_FAILED')");
            BigDecimal u=BigDecimal.ZERO,p=BigDecimal.ZERO,g=BigDecimal.ZERO;int uc=0,pc=0,gc=0;
            for(var row:rows){var amount=(BigDecimal)row.get("reserved_usd");g=g.add(amount);
                boolean owner=((Number)row.get("user_id")).longValue()==r.user(),project=((Number)row.get("project_id")).longValue()==r.project();
                if(owner)u=u.add(amount);if(project)p=p.add(amount);
                if(Boolean.TRUE.equals(row.get("hourly"))){gc++;if(owner)uc++;if(project)pc++;}}
            if(uc>=6||pc>=12||gc>=60||u.add(reserved).compareTo(userLimit)>0||p.add(reserved).compareTo(projectLimit)>0||g.add(reserved).compareTo(serviceLimit)>0)throw denied();
            if(db.update("update ai_usage_request_v1 set state='RESERVED',updated_at=current_timestamp where request_id=? and state='PREPARED'",r.requestId())!=1)throw denied();
        });}catch(RuntimeException failure){db.update("update ai_usage_request_v1 set state='PRE_SEND_FAILED',cost_status='NOT_SENT',updated_at=current_timestamp where request_id=? and state='PREPARED'",r.requestId());if(failure instanceof ExhibitLimit limit)throw limit;throw denied();}
        return r.requestId();
    }
    public void sending(String id){if(!transmissionOpen())throw denied();if(db.update("update ai_usage_request_v1 set state='SENDING',updated_at=current_timestamp where request_id=? and state='RESERVED'",id)!=1)throw denied();}
    public void complete(String id,AiTokenUsage usage){
        var cost=usage==null?null:AiCostPolicy.cost(usage);boolean known=cost!=null&&usage.usageKnown();
        if(db.update("update ai_usage_request_v1 set state=?,actual_input=?,actual_output=?,cached_input=?,usage_model=?,estimated_usd=?,cost_status=?,updated_at=current_timestamp where request_id=? and state='SENDING'",
                known?"COMPLETED":"REVIEW_REQUIRED",known?usage.promptTokens():null,known?usage.completionTokens():null,known?usage.cachedInputTokens():null,usage==null?null:usage.model(),cost,known?"ESTIMATED_FROM_API_USAGE":"USAGE_UNKNOWN",id)!=1)throw denied();
    }
    public void uncertain(String id){db.update("update ai_usage_request_v1 set state='PROVIDER_UNKNOWN',cost_status='REVIEW_REQUIRED',updated_at=current_timestamp where request_id=? and state='SENDING'",id);}
    /** Only stale requests are reconciled. No provider retry; reservations remain charged to the window. */
    public int reconcile(){return db.update("update ai_usage_request_v1 set state='PROVIDER_UNKNOWN',cost_status='REVIEW_REQUIRED',updated_at=current_timestamp where state in ('RESERVED','SENDING') and updated_at<current_timestamp-interval '5 minutes'");}
    private IllegalStateException denied(){return new IllegalStateException("AI transmission requires durable admission, explicit consent, known pricing and available budget; no retry");}
}
