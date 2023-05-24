package kz.bars.family.budget.user.api.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import kz.bars.family.budget.user.api.dto.UserDto;
import kz.bars.family.budget.user.api.payload.request.PasswordUpdateRequest;
import kz.bars.family.budget.user.api.payload.request.ProfileUpdateRequest;
import kz.bars.family.budget.user.api.service.UserAccountService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
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
    public PasswordUpdateRequest updateUserPassword(@RequestBody PasswordUpdateRequest passwordUpdateRequest) {

        log.debug("!Call method User Password update");
        return userAccountService.updateUserDtoPassword(passwordUpdateRequest);

    }

    @PutMapping("/profile")
    @Operation(description = "User Profile update")
    public ProfileUpdateRequest updateProfile(@RequestBody ProfileUpdateRequest profileUpdateRequest) {

        log.debug("!Call method User Profile update");
        return userAccountService.updateUserDtoProfile(profileUpdateRequest);

    }

    @GetMapping("/getuser")
    @Operation(description = "Get Current User")
    public UserDto getCurrentUser() {

        log.debug("!Call method get Current User");
        return userAccountService.getCurrentUserDto();

    }

}
