package com.lopessystem.authserver.repository;

import com.lopessystem.authserver.entity.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * The interface User info repository.
 */
public interface UserInfoRepository extends JpaRepository<UserInfo, Integer> {

    /**
     * Find by login optional.
     *
     * @param login the login
     * @return the optional
     */
    Optional<UserInfo> findByLogin(String login);

}
