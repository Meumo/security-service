package sn.meum.securityservice.security.service;

import sn.meum.securityservice.security.entities.AppRole;
import sn.meum.securityservice.security.entities.AppUser;

import java.util.List;

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username,String roleName);
    AppUser loadUserByUsername(String username);
     List<AppUser> listUsers();
}
