package com.baimurzin.itlabel.core.repository;

import com.baimurzin.itlabel.core.domain.AuthProviderUserDetail;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthProviderUserDetailRepository extends JpaRepository<AuthProviderUserDetail, Long> {

    Optional<AuthProviderUserDetail> findByEmail(String email);
}
