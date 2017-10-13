package com.oms.common.security.config;


import org.apache.http.HttpRequestInterceptor;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.RestTemplate;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;


@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/","/api", "/swagger-ui.html", "/actuator/**", "/configuration/**", "/webjars/**", "/swagger-resources/**", "/swagger-composite/**", "/v2/**", "/favicon.ico", "/public", "/login").permitAll()
                .antMatchers(HttpMethod.POST, "/login").permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(new JWTLoginFilter("/login", authenticationManager()), UsernamePasswordAuthenticationFilter.class)
                // And filter other requests to check the presence of JWT in header
                .addFilterBefore(new JWTAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Create a default account
        auth.inMemoryAuthentication()
                .withUser("OMSAdmin")
                .password("OMS1234")
                .roles("ADMIN");
    }

    @Bean
    public HttpRequestInterceptor apacheOutgoingTokenHeaderInterceptor() {
        return (request, context) -> {
            if (SecurityContextHolder.getContext().getAuthentication() != null) {
                Object credentials = SecurityContextHolder.getContext().getAuthentication().getCredentials();
                String token = credentials.toString();
                request.addHeader("Authorization", "Bearer " + token);
            }
        };
    }
    @Bean
    public HttpClient getHttpClient() {
        CloseableHttpClient httpClient = HttpClients.custom()
                .addInterceptorLast(apacheOutgoingTokenHeaderInterceptor()).build();
        return httpClient;
    }
    @Bean
    public ClientHttpRequestFactory getClientHttpRequestFactory() {
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(getHttpClient());
        return factory;
    }
    @LoadBalanced
    @Bean
    public RestTemplate getRestTemplate() {
        RestTemplate restTemplate = new RestTemplate(getClientHttpRequestFactory());
        return restTemplate;
    }

}
