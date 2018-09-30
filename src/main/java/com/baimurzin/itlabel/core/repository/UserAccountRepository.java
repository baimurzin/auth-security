package com.baimurzin.itlabel.core.repository;

import com.baimurzin.itlabel.core.domain.UserAccount;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserAccountRepository extends JpaRepository<UserAccount, Long> {

    Optional<UserAccount> findByUsername(String username);

    Optional<UserAccount> findByEmail(String email);

    Page<UserAccount> findByUsernameContainsIgnoreCase(Pageable springDataPage, String login);

}
