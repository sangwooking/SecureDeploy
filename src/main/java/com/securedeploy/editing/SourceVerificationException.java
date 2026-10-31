package com.securedeploy.editing;
import org.springframework.http.HttpStatus;
final class SourceVerificationException extends com.securedeploy.global.error.SecureDeployException {
    final SourceVerification verification;
    SourceVerificationException(SourceVerification value){this(HttpStatus.CONFLICT,value);}
    SourceVerificationException(HttpStatus status,SourceVerification value){super(status,value.message());verification=value;}
}
