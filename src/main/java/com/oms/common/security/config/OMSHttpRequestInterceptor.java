package com.oms.common.security.config;


import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.protocol.HttpContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;

public class OMSHttpRequestInterceptor implements HttpRequestInterceptor {

    private static final Logger LOGGER = LoggerFactory.getLogger(OMSHttpRequestInterceptor.class);

    private static final String AUTHORIZATION_HEADER = "Authorization";

    public OMSHttpRequestInterceptor() {
    }

    public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            LOGGER.info("message ={}", "Start setting token in header for IPC call");
            Object credentials = SecurityContextHolder.getContext().getAuthentication().getCredentials();
            String token = credentials.toString();
            LOGGER.info("Derived Token From Security Context ={}", "searchAllProducts");
            request.addHeader(AUTHORIZATION_HEADER, "Bearer " + token);
            LOGGER.info("message ={}", "Setting token in header for IPC call is success");
        }
    }
}
