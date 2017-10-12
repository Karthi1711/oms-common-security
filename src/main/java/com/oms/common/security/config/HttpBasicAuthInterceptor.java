package com.oms.common.security.config;


import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.protocol.HttpContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;

public class HttpBasicAuthInterceptor implements HttpRequestInterceptor {
    private static final String AUTHORIZATION_HEADER = "Authorization";

    public HttpBasicAuthInterceptor() {
    }

    public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            Object credentials = SecurityContextHolder.getContext().getAuthentication().getCredentials();
            String token = credentials.toString();
            request.addHeader(AUTHORIZATION_HEADER, "Bearer " + token);
        }
    }
}
