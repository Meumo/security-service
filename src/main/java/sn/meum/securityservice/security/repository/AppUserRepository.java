package sn.meum.securityservice.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import sn.meum.securityservice.security.entities.AppUser;

public interface AppUserRepository extends JpaRepository<AppUser,Long> {
     AppUser findByUsername(String username);
}
