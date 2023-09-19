package com.lopessystem.authserver.config;

/*
@Configuration
@EnableWebSecurity
public class ServerConfig extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("anderson")
                .password(passwordEncoder().encode("12345"))
                .roles("ADMIN")
                .and()
                .withUser("helena")
                .password(passwordEncoder().encode("12345"))
                .roles("USER");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        return super.userDetailsService();
    }
}
*/

