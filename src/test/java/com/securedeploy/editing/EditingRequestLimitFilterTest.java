package com.securedeploy.editing;

import static org.junit.jupiter.api.Assertions.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;

class EditingRequestLimitFilterTest {
    @Test void allJacksonJsonTypesAreBoundedEvenWithoutTrustedContentLength() throws Exception {
        for(String type:java.util.List.of("application/json","Application/JSON; charset=UTF-8","application/problem+json")) {
            var request=new MockHttpServletRequest("PUT","/api/editing-workspaces/a/files/b");request.setContentType(type);
            request.setContent(new byte[1024*1024+1]);
            var response=new MockHttpServletResponse();var called=new AtomicBoolean();
            new EditingRequestLimitFilter().doFilter(request,response,(req,res)->called.set(true));
            assertEquals(413,response.getStatus());assertFalse(called.get());assertEquals("no-store",response.getHeader("Cache-Control"));
        }
    }
    @Test void boundedBodyReachesJacksonUnchangedAndOtherApisAreUntouched() throws Exception {
        var filter=new EditingRequestLimitFilter();
        var request=new MockHttpServletRequest("PUT","/api/editing-workspaces/a/files/b");request.setContentType("application/json");request.setContent("{}".getBytes());
        var response=new MockHttpServletResponse();
        filter.doFilter(request,response,(req,res)->assertEquals("{}",new String(req.getInputStream().readAllBytes())));
        var other=new MockHttpServletRequest("GET","/api/reviews");var untouched=new MockHttpServletResponse();
        filter.doFilter(other,untouched,(req,res)->assertSame(other,req));assertNull(untouched.getHeader("Cache-Control"));
    }
}
