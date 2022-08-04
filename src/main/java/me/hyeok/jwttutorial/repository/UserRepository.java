package me.hyeok.jwttutorial.repository;

import me.hyeok.jwttutorial.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    // EntityGraph 은 쿼리가 수행될 떄 LAZY 조회가 아니고 Eager 조회로 authorities 정보를 같이 가져옴
    @EntityGraph(attributePaths = "authorities")
    Optional<User> findOneWithAuthoritiesByUsername(String username);   // findOneWithAuthoritiesByUsername =>
                                                                        // username 을 기준으로 User 정보를 가져올때권한 정보도 같이 가져옴

}
