package com.lopessystem.authserver.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .inMemory()
                .withClient("clinic-api")
                .secret(passwordEncoder.encode("api-123"))
                .authorizedGrantTypes("password", "refresh_token", "client_credentials")
                .scopes("write", "read")
                .accessTokenValiditySeconds(60 * 5) // 5 minutes
                .refreshTokenValiditySeconds(60 * 60 * 5) // 5 hours

                .and()
                .withClient("resource-server-app")
                .secret(passwordEncoder.encode("check123"))

                .and()
                .withClient("email-service")
                .secret(passwordEncoder.encode("email-ms-123"))
                .authorizedGrantTypes("client_credentials")
                .scopes("read")
                // example url called by client in order to retrieve authorization code
                // http://localhost:9000/oauth/authorize?response_type=code&client_id=power-bi-app&state=abc&redirect_uri=http://power-bi-app/authorize
                // returns: http://power-bi-app/authorize?code=oy-XBH&state=abc
                .and()
                .withClient("power-bi-app")
                .secret(passwordEncoder.encode("powerBi123"))
                .authorizedGrantTypes("authorization_code")
                .redirectUris("http://localhost:8082")
                .scopes("write", "read")
                // example url called by client in order to retrieve an access token
                // http://localhost:9000/oauth/authorize?response_type=token&client_id=webadmin&state=abc&redirect_uri=http://webadmin/home
                // return: http://webadmin/home#access_token=-GiMcyra44YOyU5BwumSGywh5Co&token_type=bearer&state=abc&expires_in=43199&scope=read%20write
                .and()
                .withClient("webadmin")
                .authorizedGrantTypes("implicit")
                .redirectUris("http://webadmin/home")
                .scopes("write", "read");

    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        // security.checkTokenAccess("isAuthenticated()");
        security.checkTokenAccess("permitAll()");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)
                .reuseRefreshTokens(false)
                .tokenStore(redisTokenStore());
    }

    private TokenStore redisTokenStore() {
        return new RedisTokenStore(redisConnectionFactory);
    }
}
