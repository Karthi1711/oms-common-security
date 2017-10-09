package com.oms.common.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnableAutoConfiguration
public class CommonSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(CommonSecurityApplication.class, args);
	}
}
