package com.securedeploy.global.error;

import java.time.LocalDateTime;
import com.securedeploy.upload.service.UploadPolicy;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private final UploadPolicy uploadPolicy;

    public GlobalExceptionHandler(UploadPolicy uploadPolicy) {
        this.uploadPolicy = uploadPolicy;
    }

    @ExceptionHandler({org.springframework.web.method.annotation.MethodArgumentTypeMismatchException.class,
            org.springframework.http.converter.HttpMessageNotReadableException.class})
    public ResponseEntity<ErrorResponse> handleInvalidRequestFormat(Exception exception) {
        return ResponseEntity.badRequest().body(new ErrorResponse(LocalDateTime.now(), 400, "Bad Request",
                "요청 형식이 올바르지 않습니다. scanMode는 STANDARD 또는 AI_ENHANCED를 사용해 주세요."));
    }

    @ExceptionHandler(SecureDeployException.class)
    public ResponseEntity<ErrorResponse> handleSecureDeployException(SecureDeployException exception) {
        HttpStatus status = exception.getStatus();
        return ResponseEntity.status(status)
                .body(new ErrorResponse(LocalDateTime.now(), status.value(), status.getReasonPhrase(), exception.getMessage(),
                        exception instanceof com.securedeploy.project.coverage.CoverageException failure ? failure.coverage() : null));
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<ErrorResponse> handleMaxUploadSizeExceededException(MaxUploadSizeExceededException exception) {
        return handleSecureDeployException(uploadPolicy.reject("MULTIPART_LIMIT", HttpStatus.PAYLOAD_TOO_LARGE,
                uploadPolicy.uploadLimitMessage(), -1, 0, 0));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationException(MethodArgumentNotValidException exception) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        String message = exception.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(fieldError -> fieldError.getDefaultMessage() == null ? "요청 값이 올바르지 않습니다." : fieldError.getDefaultMessage())
                .orElse("요청 값이 올바르지 않습니다.");
        return ResponseEntity.status(status)
                .body(new ErrorResponse(LocalDateTime.now(), status.value(), status.getReasonPhrase(), message));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleException(Exception exception) {
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        return ResponseEntity.status(status)
                .body(new ErrorResponse(LocalDateTime.now(), status.value(), status.getReasonPhrase(), "서버 처리 중 오류가 발생했습니다. 잠시 후 다시 시도해 주세요."));
    }
}
