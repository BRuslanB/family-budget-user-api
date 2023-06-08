package kz.bars.family.budget.user.api.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import kz.bars.family.budget.user.api.dto.UserDto;
import kz.bars.family.budget.user.api.exeption.UserNotFoundException;
import kz.bars.family.budget.user.api.exeption.UserPasswordMismatchException;
import kz.bars.family.budget.user.api.payload.request.PasswordUpdateRequest;
import kz.bars.family.budget.user.api.payload.request.ProfileUpdateRequest;
import kz.bars.family.budget.user.api.payload.response.MessageResponse;
import kz.bars.family.budget.user.api.service.UserAccountService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping(value = "/api/users")
@CrossOrigin
@Log4j2
@PreAuthorize("isAuthenticated()")
@SecurityRequirement(name = "family-budget-user-api")
@Tag(name = "User Account", description = "All methods of using a User Account")
public class UserAccountController {
    private final UserAccountService userAccountService;

    @PutMapping("/password")
    @Operation(description = "User Password update")
    public ResponseEntity<Object> updateUserPassword(@RequestBody PasswordUpdateRequest passwordUpdateRequest) {

        log.debug("!Call method User Password update");

        try {
            PasswordUpdateRequest passwordUpdate = userAccountService.updateUserDtoPassword(passwordUpdateRequest);

            if (passwordUpdate != null) {
                return ResponseEntity.ok(new MessageResponse("User Password updated successfully!"));
            }
        } catch (UserNotFoundException | UserPasswordMismatchException e) {
            return new ResponseEntity<>(new MessageResponse(e.getMessage()), HttpStatus.BAD_REQUEST);
        }

        return new ResponseEntity<>(new MessageResponse("User Password not updated"), HttpStatus.BAD_REQUEST);
    }

    @PutMapping("/profile")
    @Operation(description = "User Profile update")
    public ResponseEntity<Object> updateProfile(@RequestBody ProfileUpdateRequest profileUpdateRequest) {

        log.debug("!Call method User Profile update");

        try {
            ProfileUpdateRequest profileUpdate = userAccountService.updateUserDtoProfile(profileUpdateRequest);

            if (profileUpdate != null) {
                return ResponseEntity.ok(new MessageResponse("User Profile updated successfully!"));
            }
        } catch (UserNotFoundException e) {
            return new ResponseEntity<>(new MessageResponse(e.getMessage()), HttpStatus.BAD_REQUEST);
        }

        return new ResponseEntity<>(new MessageResponse("User Profile not updated"), HttpStatus.BAD_REQUEST);
    }

    @GetMapping("/getuser")
    @Operation(description = "Get Current User")
    public ResponseEntity<Object> getCurrentUser() {

        log.debug("!Call method get Current User");

        try {
            UserDto userDto = userAccountService.getCurrentUserDto();

            if (userDto != null) {
                return ResponseEntity.ok(userDto);
            }
        } catch (UserNotFoundException e) {
            return new ResponseEntity<>(new MessageResponse(e.getMessage()), HttpStatus.BAD_REQUEST);
        }

        return new ResponseEntity<>(new MessageResponse("User not found"), HttpStatus.BAD_REQUEST);
    }

}
