package com.bezkoder.springjwt.security.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.bezkoder.springjwt.models.User;
import com.bezkoder.springjwt.repository.UserRepository;
import org.springframework.util.StringUtils;

import java.util.Optional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
  @Autowired
  UserRepository userRepository;

  @Override
  @Transactional
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

    return UserDetailsImpl.build(user);
  }

  @Transactional
  public String loadUserLastFourSSN(Long id) throws Exception {
    User user = userRepository.findById(id)
            .orElseThrow(() -> new UsernameNotFoundException("User Not Found with id: " + id));
    String encodedSSN = user.getSsn();
    if(encodedSSN != null){
      String ssn = EncryptionUtil.decryptSSN(encodedSSN);
      String lastFour = "***-**-" + ssn.substring(ssn.length() - 4);
      return lastFour;
    }

    return null;
  }

}
