package org.test.webfluxsecurity.repository;

import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.test.webfluxsecurity.entity.UserEntity;
import reactor.core.publisher.Mono;

public interface UserRepository extends R2dbcRepository<UserEntity, Long> {
    Mono<UserEntity> findByUsername(String username);
}
