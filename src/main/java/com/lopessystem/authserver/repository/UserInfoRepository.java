package com.lopessystem.authserver.repository;

import com.lopessystem.authserver.entity.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserInfoRepository extends JpaRepository<UserInfo, Integer> {
    Optional<UserInfo> findByLogin(String login);

}
