package org.test.webfluxsecurity.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.test.webfluxsecurity.security.AuthenticationManager;
import org.test.webfluxsecurity.security.BearerTokenServerAuthenticationConverter;
import org.test.webfluxsecurity.security.JwtHandler;
import reactor.core.publisher.Mono;

@Slf4j
@Configuration
@EnableReactiveMethodSecurity
public class WebSecurityConfig {

    @Value("${jwt.secret}")
    private String secret;

    private final String[] publicRoutes = {"/api/v1/auth/register", "/api/v1/auth/login"};

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http, AuthenticationManager authenticationManager) {
        return http
                .csrf(
                        csrfSpec -> csrfSpec
                                .disable()
                                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec
                                        .pathMatchers(HttpMethod.OPTIONS)
                                        .permitAll()
                                        .pathMatchers(publicRoutes)
                                        .permitAll()
                                        .anyExchange()
                                        .authenticated())
                )
                .exceptionHandling(
                        exceptionHandlingSpec -> exceptionHandlingSpec.authenticationEntryPoint((swe, e) -> {
                            log.error("IN securityWebFilterChain - unauthorized error: {}", e.getMessage());
                            return Mono.fromRunnable(() -> {
                                swe.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            });
                        }).accessDeniedHandler((swe, e) -> {
                            log.error("IN securityWebFilterChain - access denied: {}", e.getMessage());
                            return Mono.fromRunnable(() -> {
                                swe.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                            });
                        })
                )
                .addFilterAt(bearerAuthenticationFilter(authenticationManager), SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    public AuthenticationWebFilter bearerAuthenticationFilter(AuthenticationManager authenticationManager) {
        AuthenticationWebFilter bearerAuthenticationWebFilter = new AuthenticationWebFilter((authenticationManager));
        bearerAuthenticationWebFilter.setServerAuthenticationConverter(new BearerTokenServerAuthenticationConverter(new JwtHandler(secret)));
        bearerAuthenticationWebFilter.setRequiresAuthenticationMatcher(ServerWebExchangeMatchers.pathMatchers("/**"));
        return bearerAuthenticationWebFilter;
    }

}

