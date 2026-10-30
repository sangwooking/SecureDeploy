package com.securedeploy.editing;
import com.securedeploy.global.error.SecureDeployException;
import org.springframework.http.HttpStatus;
final class EditingConflictException extends SecureDeployException {
    final String code;
    EditingConflictException(String code,String message){super(HttpStatus.CONFLICT,message);this.code=code;}
}
