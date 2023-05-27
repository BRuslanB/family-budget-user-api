package kz.bars.family.budget.user.api.service.impl;

import kz.bars.family.budget.user.api.dto.UserDto;
import kz.bars.family.budget.user.api.exeption.UserAlreadyExistsException;
import kz.bars.family.budget.user.api.exeption.UserNotFoundException;
import kz.bars.family.budget.user.api.exeption.UserPasswordMismatchException;
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
import org.springframework.security.core.context.SecurityContextHolder;
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

        try {
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
                            signupRequest.getEmail(),
                            signupRequest.getFirstName(),
                            signupRequest.getLastName(),
                            signupRequest.getBirthDay(),
                            signupRequest.getPassword().replaceAll(".", "*"),
                            signupRequest.getRePassword().replaceAll(".", "*"));

                    return signupRequest;

                } else {

                    log.debug("!User password mismatch, email={}, password={}, repeat password={}" +
                                    signupRequest.getEmail(),
                            signupRequest.getPassword().replaceAll(".", "*"),
                            signupRequest.getRePassword().replaceAll(".", "*"));

                    throw new UserPasswordMismatchException("Password mismatch");
                }

            } else {

                log.error("!User already exists, email={}" + signupRequest.getEmail());
                throw new UserAlreadyExistsException("User already exists");
            }

        } catch (Exception ex) {

            log.error("!User not registered, " +
                            "email={}, first_name={}, last_name={}, birth_day={}, password={}, repeat_password={}",
                    signupRequest.getEmail(),
                    signupRequest.getFirstName(),
                    signupRequest.getLastName(),
                    signupRequest.getBirthDay(),
                    signupRequest.getPassword().replaceAll(".", "*"),
                    signupRequest.getRePassword().replaceAll(".", "*"));
        }

        return null;
    }

    @Override
    public PasswordUpdateRequest updateUserDtoPassword(PasswordUpdateRequest passwordUpdateRequest) {

        try {
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

        } catch (Exception ex) {

            log.error("!User has not updated the Password, old_password={}, new_password={}, renew_password={}",
                    passwordUpdateRequest.getPassword().replaceAll(".", "*"),
                    passwordUpdateRequest.getNewPassword().replaceAll(".", "*"),
                    passwordUpdateRequest.getRePassword().replaceAll(".", "*"));
        }

        return null;
    }

    @Override
    public ProfileUpdateRequest updateUserDtoProfile(ProfileUpdateRequest profileUpdateRequest) {

        try {
            User currentUser = userService.getCurrentUser();

            if (currentUser != null) {

                if (true) {
                    currentUser.setFirstname(profileUpdateRequest.getFirstName());
                    currentUser.setLastname(profileUpdateRequest.getLastName());
                    currentUser.setBirthDay(profileUpdateRequest.getBirthDay());

                    userRepo.save(currentUser);

                    log.debug("!User updated the Profile successfully, first_name={}, last_name={}, birth_day={}",
                            profileUpdateRequest.getFirstName(),
                            profileUpdateRequest.getLastName(),
                            profileUpdateRequest.getBirthDay());

                    return profileUpdateRequest;
                }

            } else {

                throw new UserNotFoundException("User not found");
            }

        } catch (Exception ex) {

            log.error("!User has not updated the Profile, first_name={}, last_name={}, birth_day={}",
                    profileUpdateRequest.getFirstName(),
                    profileUpdateRequest.getLastName(),
                    profileUpdateRequest.getBirthDay());
        }

        return null;
    }

    @Override
    public UserDto getCurrentUserDto() {

        try {
            User currentUser = userService.getCurrentUser();

            if (currentUser != null) {
                UserDto userDto = new UserDto();
                userDto.setEmail(currentUser.getEmail());
                userDto.setFirstName(currentUser.getFirstname());
                userDto.setLastName(currentUser.getLastname());
                userDto.setBirthDay(currentUser.getBirthDay());

                log.debug("!Current user, name={}",
                        SecurityContextHolder.getContext().getAuthentication().getName());

                return userDto;

            } else {

                throw new UserNotFoundException("User not found");
            }

        } catch (Exception ex) {

            log.error("!Current user not found");
        }

        return null;
    }

}
