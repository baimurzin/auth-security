package com.baimurzin.itlabel.core.service.impl;

import com.baimurzin.itlabel.core.repository.UserAccountRepository;
import com.baimurzin.itlabel.core.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private UserAccountRepository userAccountRepository;

}
