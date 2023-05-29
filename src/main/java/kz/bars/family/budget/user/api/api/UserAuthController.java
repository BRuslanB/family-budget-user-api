package kz.bars.family.budget.user.api.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import kz.bars.family.budget.user.api.exeption.TokenExpiredException;
import kz.bars.family.budget.user.api.exeption.UserAlreadyExistsException;
import kz.bars.family.budget.user.api.exeption.UserNotFoundException;
import kz.bars.family.budget.user.api.exeption.UserPasswordMismatchException;
import kz.bars.family.budget.user.api.payload.request.LoginRequest;
import kz.bars.family.budget.user.api.payload.request.RefreshTokenRequest;
import kz.bars.family.budget.user.api.payload.request.SignupRequest;
import kz.bars.family.budget.user.api.payload.response.MessageResponse;
import kz.bars.family.budget.user.api.payload.response.TokenSuccessResponse;
import kz.bars.family.budget.user.api.service.UserAccountService;
import kz.bars.family.budget.user.api.service.UserAuthService;
import kz.bars.family.budget.user.api.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@CrossOrigin
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Log4j2
@SecurityRequirement(name = "family-budget-user-api")
@Tag(name = "User Account", description = "Methods for User Authentication")
public class UserAuthController {

    final UserService userService;
    final UserAuthService userAuthService;
    final UserAccountService userAccountService;

    @PostMapping("/signin")
    @PreAuthorize("permitAll()")
    @Operation(description = "User authentication")
    public ResponseEntity<Object> authenticateUser(@RequestBody LoginRequest loginRequest) {

        log.debug("!Call method User authentication");

        try {
            TokenSuccessResponse tokenSuccessResponse = userAuthService.authenticateUser(loginRequest);

            if (tokenSuccessResponse != null) {
                return ResponseEntity.ok(tokenSuccessResponse);
            }
        } catch (UserNotFoundException e) {
            return new ResponseEntity<>(new MessageResponse(e.getMessage()), HttpStatus.BAD_REQUEST);
        }

        return new ResponseEntity<>(new MessageResponse("Invalid User Credentials"), HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/refreshtoken")
    @PreAuthorize("isAuthenticated()")
    @Operation(description = "Refresh tokens authentication")
    public ResponseEntity<Object> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {

        log.debug("!Call method Refresh tokens authentication");

        try {
            if (refreshTokenRequest.getEmail() != null) {
                TokenSuccessResponse tokenSuccessResponse = userAuthService.refreshToken(refreshTokenRequest);

                if (tokenSuccessResponse != null) {
                    return ResponseEntity.ok(tokenSuccessResponse);
                }
            }
        } catch (UserNotFoundException e) { //
            return new ResponseEntity<>(new MessageResponse(e.getMessage()), HttpStatus.BAD_REQUEST);
        }

        return new ResponseEntity<>(new MessageResponse("Invalid Refresh Token or User not found"), HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/signup")
    @PreAuthorize("permitAll()")
    @Operation(description = "User registration")
    public ResponseEntity<Object> registerUser(@RequestBody SignupRequest signupRequest) {

        log.debug("!Call method User registration");

        try {
            if (userAccountService.registerUserDto(signupRequest) != null) {
                return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
            }
        } catch (UserAlreadyExistsException | UserPasswordMismatchException e) {
            return new ResponseEntity<>(new MessageResponse(e.getMessage()), HttpStatus.BAD_REQUEST);
        }

        return new ResponseEntity<>(new MessageResponse("User not registered"), HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/signout")
    @PreAuthorize("isAuthenticated()")
    @Operation(description = "User logout")
    public ResponseEntity<Void> logoutUser() {

        log.debug("!Call method User logout");
        userAuthService.logoutUser();

        return ResponseEntity.noContent().build();
    }

}
