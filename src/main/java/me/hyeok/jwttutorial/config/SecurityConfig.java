package me.hyeok.jwttutorial.config;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity  // 기본적인 web 보안 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .antMatchers(  // 관련된 것들은 무시
                        "h2-console/**"
                        , "/favicon.ico"
                );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()   // httpServletRequest 를 사용하는 요청들을 접근제한 설정
                .antMatchers("/api/hello").permitAll()  // "/api/hello" 에 대한 요청은 인증없이 접근 허용
                .anyRequest().authenticated();      // 나머지 요청들은 인증을 받아야 함
    }
}
