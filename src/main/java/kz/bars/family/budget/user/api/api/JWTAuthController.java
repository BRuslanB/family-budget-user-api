package kz.bars.family.budget.user.api.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import kz.bars.family.budget.user.api.JWT.JWTSecurityConstants;
import kz.bars.family.budget.user.api.JWT.JWTTokenProvider;
import kz.bars.family.budget.user.api.dto.UserDto;
import kz.bars.family.budget.user.api.model.User;
import kz.bars.family.budget.user.api.payload.request.LoginRequest;
import kz.bars.family.budget.user.api.payload.request.SignupRequest;
import kz.bars.family.budget.user.api.payload.response.JWTTokenSuccessResponse;
import kz.bars.family.budget.user.api.payload.response.MessageResponse;
import kz.bars.family.budget.user.api.service.UserAccountService;
import kz.bars.family.budget.user.api.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Log4j2
@SecurityRequirement(name = "family-budget-user-api")
@Tag(name = "User Account", description = "Methods for User Authentication")
public class JWTAuthController {

    final AuthenticationManager authenticationManager;
    final JWTTokenProvider jwtTokenProvider;
    final UserService userService;
    final UserAccountService userAccountService;

    @GetMapping("/getuser")
    @PreAuthorize("isAuthenticated()")
    @Operation(description = "Get Current User")
    public ResponseEntity<Object> getCurrentUser() {

        log.debug("!Call method get Current User");
        User user = userService.getCurrentUser();

        if (user != null) {
            UserDto userDto = new UserDto();
            userDto.setEmail(user.getEmail());
            userDto.setFirstName(user.getFirstname());
            userDto.setLastName(user.getLastname());
            userDto.setBirthDay(user.getBirthDay());

            log.debug("!Current user, name={}",
                    SecurityContextHolder.getContext().getAuthentication().getName());

            return new ResponseEntity<>(userDto, HttpStatus.OK);
        }
        log.error("!No authorized user");

        return new ResponseEntity<>(new MessageResponse("No authorized user"), HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/signin")
    @PreAuthorize("permitAll()")
    @Operation(description = "User authentication")
    public ResponseEntity<Object> authenticateUser(@RequestBody LoginRequest loginRequest) {

        log.debug("!Call method User authentication");

        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    loginRequest.getEmail(), loginRequest.getPassword()));

            if (authentication.isAuthenticated()) {

                SecurityContextHolder.getContext().setAuthentication(authentication);

                List<String> authorities = new ArrayList<>();
                for (GrantedAuthority grantedAuthority : authentication.getAuthorities()) {
                    authorities.add(grantedAuthority.getAuthority());
                }
                String jwt = JWTSecurityConstants.TOKEN_PREFIX +
                        jwtTokenProvider.generateToken(loginRequest.getEmail(), authorities);

                return ResponseEntity.ok(new JWTTokenSuccessResponse(true, jwt));
            }

        } catch (Exception ex) {

            log.error("!Invalid user credentials, email={}, password={}",
                    loginRequest.getEmail(), loginRequest.getPassword().replaceAll(".", "*"));
        }

        return new ResponseEntity<>(new MessageResponse("Invalid user credentials"), HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/signup")
    @PreAuthorize("permitAll()")
    @Operation(description = "User registration")
    public ResponseEntity<Object> registerUser(@RequestBody SignupRequest signupRequest) {

        log.debug("!Call method User registration");

        if (userAccountService.registerUserDto(signupRequest) != null) {
            return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
        }

        return new ResponseEntity<>(new MessageResponse("User not registered"), HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/signout")
    @PreAuthorize("isAuthenticated()")
    @Operation(description = "User logout")
    public ResponseEntity<Void> logoutUser() {

        log.debug("!Call method User logout");
        log.debug("!User logout, name={}",
                SecurityContextHolder.getContext().getAuthentication().getName());

        SecurityContextHolder.clearContext();
        return ResponseEntity.noContent().build();
    }

}
