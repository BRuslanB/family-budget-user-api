package kz.bars.family.budget.user.api.service.impl;

import kz.bars.family.budget.user.api.exeption.UserAlreadyExistsException;
import kz.bars.family.budget.user.api.exeption.UserNotFoundException;
import kz.bars.family.budget.user.api.model.Role;
import kz.bars.family.budget.user.api.model.User;
import kz.bars.family.budget.user.api.payload.request.PasswordUpdateRequest;
import kz.bars.family.budget.user.api.payload.request.ProfileUpdateRequest;
import kz.bars.family.budget.user.api.payload.request.SignupRequest;
import kz.bars.family.budget.user.api.repository.RoleRepo;
import kz.bars.family.budget.user.api.repository.UserRepo;
import kz.bars.family.budget.user.api.service.UserAccountService;
import kz.bars.family.budget.user.api.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Log4j2
public class UserAccountServiceImpl implements UserAccountService {

    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepo roleRepo;
    private final UserService userService;

    public SignupRequest registerUserDto(SignupRequest signupRequest) {

        User checkUser = userRepo.findByEmail(signupRequest.getEmail());

        if (checkUser == null) {
            if (signupRequest.getPassword().equals(signupRequest.getRePassword())) {

                List<Role> roles = new ArrayList<>();
                Role userRole = roleRepo.findByRole("ROLE_USER");
                roles.add(userRole);

                User user = User
                        .builder()
                        .email(signupRequest.getEmail())
                        .firstname(signupRequest.getFirstName())
                        .lastname(signupRequest.getLastName())
                        .birthDay(signupRequest.getBirthDay())
                        .roles(roles)
                        .password(passwordEncoder.encode(signupRequest.getPassword()))
                        .build();

                userRepo.save(user);

                log.debug("!User successfully registered, " +
                                "email={}, first_name={}, last_name={}, birth_day={}, password={}, repeat_password={}",
                        signupRequest.getEmail(), signupRequest.getFirstName(), signupRequest.getLastName(),
                        signupRequest.getBirthDay(),
                        signupRequest.getPassword().replaceAll(".", "*"),
                        signupRequest.getRePassword().replaceAll(".", "*"));

                return signupRequest;
            }

        } else {

            throw new UserAlreadyExistsException("User already exists");
        }

        log.error("!User not registered, email={}, first_name={}, last_name={}, birth_day={}, " +
                        "password={}, repeat password={}",
                signupRequest.getEmail(), signupRequest.getFirstName(), signupRequest.getLastName(),
                signupRequest.getBirthDay(),
                signupRequest.getPassword().replaceAll(".", "*"),
                signupRequest.getRePassword().replaceAll(".", "*"));

        return null;
    }

    @Override
    public PasswordUpdateRequest updateUserDtoPassword(PasswordUpdateRequest passwordUpdateRequest) {

        User currentUser = userService.getCurrentUser();

        if (currentUser != null) {
            if (passwordUpdateRequest.getNewPassword().equals(passwordUpdateRequest.getRePassword()) &&
                    passwordEncoder.matches(passwordUpdateRequest.getPassword(), currentUser.getPassword())) {
                currentUser.setPassword(passwordEncoder.encode(passwordUpdateRequest.getNewPassword()));

                userRepo.save(currentUser);

                log.debug("!User updated the Password successfully, old_password={}, new_password={}, " +
                                "renew_password={}",
                        passwordUpdateRequest.getPassword().replaceAll(".", "*"),
                        passwordUpdateRequest.getNewPassword().replaceAll(".", "*"),
                        passwordUpdateRequest.getRePassword().replaceAll(".", "*"));

                return passwordUpdateRequest;
            }

        } else {

            throw new UserNotFoundException("User not found");
        }

        log.error("!User has not updated the Password, old_password={}, new_password={}, renew_password={}",
                passwordUpdateRequest.getPassword().replaceAll(".", "*"),
                passwordUpdateRequest.getNewPassword().replaceAll(".", "*"),
                passwordUpdateRequest.getRePassword().replaceAll(".", "*"));

        return null;
    }

    @Override
    public ProfileUpdateRequest updateUserDtoProfile(ProfileUpdateRequest profileUpdateRequest) {

        User currentUser = userService.getCurrentUser();

        if (currentUser != null) {

            if (true) {
                currentUser.setFirstname(profileUpdateRequest.getFirstName());
                currentUser.setLastname(profileUpdateRequest.getLastName());
                currentUser.setBirthDay(profileUpdateRequest.getBirthDay());

                userRepo.save(currentUser);

                log.debug("!User updated the Profile successfully, first_name={}, last_name={}, birth_day={}",
                        profileUpdateRequest.getFirstName(), profileUpdateRequest.getLastName(),
                        profileUpdateRequest.getBirthDay());

                return profileUpdateRequest;
            }

        } else {

            throw new UserNotFoundException("User not found");
        }

        log.error("!User has not updated the Profile, first_name={}, last_name={}, birth_day={}",
                profileUpdateRequest.getFirstName(), profileUpdateRequest.getLastName(),
                profileUpdateRequest.getBirthDay());

        return null;
    }

}
