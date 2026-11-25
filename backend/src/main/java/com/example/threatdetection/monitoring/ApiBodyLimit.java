package com.example.threatdetection.monitoring;

import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdviceAdapter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;

@RestControllerAdvice
class ApiBodyLimit extends RequestBodyAdviceAdapter {
    private static final int MONITORING_MAX_BYTES = 512;
    private static final int API_MAX_BYTES = 8192;

    @Override
    public boolean supports(MethodParameter parameter, Type type,
                            Class<? extends HttpMessageConverter<?>> converter) {
        return true;
    }

    @Override
    public HttpInputMessage beforeBodyRead(HttpInputMessage input, MethodParameter parameter, Type type,
                                           Class<? extends HttpMessageConverter<?>> converter) throws IOException {
        int limit = parameter.getContainingClass() == MonitoringController.class ? MONITORING_MAX_BYTES : API_MAX_BYTES;
        if (input.getHeaders().getContentLength() > limit) throw tooLarge();
        byte[] body = input.getBody().readNBytes(limit + 1);
        if (body.length > limit) throw tooLarge();
        return new HttpInputMessage() {
            @Override
            public HttpHeaders getHeaders() { return input.getHeaders(); }

            @Override
            public InputStream getBody() { return new ByteArrayInputStream(body); }
        };
    }

    private static ResponseStatusException tooLarge() {
        return new ResponseStatusException(HttpStatus.CONTENT_TOO_LARGE);
    }
}
