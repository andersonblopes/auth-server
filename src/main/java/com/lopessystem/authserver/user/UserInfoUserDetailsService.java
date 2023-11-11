package com.lopessystem.authserver.user;

import com.lopessystem.authserver.entity.Role;
import com.lopessystem.authserver.entity.User;
import com.lopessystem.authserver.repository.UserInfoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
        User user = repository.findByLogin(login)
                .orElseThrow(() -> new UsernameNotFoundException("user not found " + login));

        return new org.springframework.security.core.userdetails.User(
                user.getLogin(), user.getPassword(), getAuthorities(user));
    }

    /**
     * Gets authorities.
     *
     * @param user the user
     * @return the authorities
     */
    public Collection<GrantedAuthority> getAuthorities(User user) {
        List<GrantedAuthority> list = new ArrayList<>();
        for (Role role : user.getRoles()) {
            SimpleGrantedAuthority authority = new SimpleGrantedAuthority(role.getRole());
            list.add(authority);
        }
        return list;
    }
}
