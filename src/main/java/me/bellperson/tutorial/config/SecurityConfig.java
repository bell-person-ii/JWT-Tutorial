package me.bellperson.tutorial.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity // 기본적인 웹 보안 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(WebSecurity web){
        web.ignoring().antMatchers(
                "/favicon.ico"
        );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http
                .authorizeRequests()// HttpServletRequest 를 사용 하는 요청에 대한 접근 제한 설정
                .antMatchers("/api/hello").permitAll()// "/api/hello" url로의 접근은 인증 없이 허용
                .anyRequest().authenticated(); // 그외의 요청들에 대해서는 모두 인증을 거쳐야 함

    }
}
