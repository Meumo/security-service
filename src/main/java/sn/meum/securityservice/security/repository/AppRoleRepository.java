package sn.meum.securityservice.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import sn.meum.securityservice.security.entities.AppRole;

public interface AppRoleRepository extends JpaRepository<AppRole,Long> {
     AppRole findByRoleName(String roleName);
}
