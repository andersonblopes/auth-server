package com.lopessystem.authserver.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class ServerConfig {

    @Bean
    InMemoryUserDetailsManager inMemoryUserDetailsManager(PasswordEncoder encoder) {
        var user1 = User.withUsername("anderson").password(encoder.encode("password")).roles("ADMIN", "USER").build();
        var user2 = User.withUsername("helena").password(encoder.encode("password")).roles("USER").build();
        return new InMemoryUserDetailsManager(user1, user2);
    }

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }
}

