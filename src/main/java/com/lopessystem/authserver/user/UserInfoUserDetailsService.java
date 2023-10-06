package com.lopessystem.authserver.user;

import com.lopessystem.authserver.entity.Role;
import com.lopessystem.authserver.entity.UserInfo;
import com.lopessystem.authserver.repository.UserInfoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * The type User info user details service.
 */
@Component
public class UserInfoUserDetailsService implements UserDetailsService {

    @Autowired
    private UserInfoRepository repository;

    @Transactional(readOnly = true)
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserInfo userInfo = repository.findByLogin(username)
                .orElseThrow(() -> new UsernameNotFoundException("user not found " + username));

        return new User(userInfo.getLogin(), userInfo.getPassword(), getAuthorities(userInfo));
    }

    /**
     * Gets authorities.
     *
     * @param userInfo the user info
     * @return the authorities
     */
    public Collection<GrantedAuthority> getAuthorities(UserInfo userInfo) {
        List<GrantedAuthority> list = new ArrayList<>();
        for (Role role : userInfo.getRoles()) {
            SimpleGrantedAuthority authority = new SimpleGrantedAuthority(role.getPermission());
            list.add(authority);
        }
        return list;
    }
}
