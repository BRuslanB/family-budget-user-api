package kz.bars.family.budget.user.api.service.impl;

import kz.bars.family.budget.user.api.JWT.JWTSecurityConstants;
import kz.bars.family.budget.user.api.JWT.JWTTokenProvider;
import kz.bars.family.budget.user.api.exeption.UserNotFoundException;
import kz.bars.family.budget.user.api.model.Role;
import kz.bars.family.budget.user.api.model.User;
import kz.bars.family.budget.user.api.payload.request.LoginRequest;
import kz.bars.family.budget.user.api.payload.request.RefreshTokenRequest;
import kz.bars.family.budget.user.api.payload.response.TokenSuccessResponse;
import kz.bars.family.budget.user.api.repository.UserRepo;
import kz.bars.family.budget.user.api.service.UserAuthService;
import kz.bars.family.budget.user.api.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Log4j2
public class UserAuthServiceImpl implements UserAuthService {

    final UserRepo userRepo;
    final JWTTokenProvider jwtTokenProvider;
    final UserService userService;
    final AuthenticationManager authenticationManager;

    @Override
    public TokenSuccessResponse authenticateUser(LoginRequest loginRequest) {

        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    loginRequest.getEmail(), loginRequest.getPassword()));

            if (authentication.isAuthenticated()) {

                SecurityContextHolder.getContext().setAuthentication(authentication);
                User user = userService.getCurrentUser();

                if (user != null) {
                    String accessToken = jwtTokenProvider.generateAccessToken(user.getEmail(),
                            user.getLastname() + " " + user.getFirstname(),
                            user.getRoles().stream().map(Role::getRole).collect(Collectors.toList()));
                    String refreshToken = jwtTokenProvider.generateRefreshToken(user.getEmail());

                    // Update the new value of the token_UUID in the database
                    String tokenUUID = jwtTokenProvider.extractUUIDFromToken(refreshToken,
                            JWTSecurityConstants.REFRESH_SECRET_KEY);

                    updateRefreshTokenInDatabase(user, tokenUUID);
                    return new TokenSuccessResponse(accessToken, refreshToken);

                } else {

                    throw new UserNotFoundException("User not found");
                }
            }

        } catch (UserNotFoundException ex) {

            throw ex; // Пропускаем обработку и выбрасываем исключение дальше

        } catch (Exception ex) {

            log.error("!Invalid user credentials, email={}, password={}",
                    loginRequest.getEmail(), loginRequest.getPassword().replaceAll(".", "*"));
        }

        return null;
    }

    @Override
    public TokenSuccessResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {

        try {
            User user = userRepo.findByEmail(refreshTokenRequest.getEmail());

            if (user != null) {
                String newAccessToken = jwtTokenProvider.generateAccessToken(user.getEmail(),
                        user.getLastname() + " " + user.getFirstname(),
                        user.getRoles().stream().map(Role::getRole).collect(Collectors.toList()));
                String newRefreshToken = jwtTokenProvider.generateRefreshToken(user.getEmail());

                // Checking the existing and saving the new value of the token_UUID in the database
                if (updateRefreshTokenInDatabase(user, refreshTokenRequest.getTokenUUID(), newRefreshToken)) {
                    return new TokenSuccessResponse(newAccessToken, newRefreshToken);
                }

            } else {

                throw new UserNotFoundException("User not found");
            }

        } catch (UserNotFoundException ex) {

            throw ex; // Пропускаем обработку и выбрасываем исключение дальше

        } catch (Exception ex) {

            log.error("!Invalid refresh token or user not found");
        }

        return null;
    }

    @Override
    public void logoutUser() {

        log.debug("!User logout, name={}",
                SecurityContextHolder.getContext().getAuthentication().getName());

        SecurityContextHolder.clearContext();
    }

    private boolean updateRefreshTokenInDatabase(User user, String tokenUUID, String newRefreshToken) {

        try {
            String currentTokenUUID = user.getTokenUUID();
            String newTokenUUID = jwtTokenProvider.extractUUIDFromToken(newRefreshToken,
                    JWTSecurityConstants.REFRESH_SECRET_KEY);

            if (currentTokenUUID == null) {
                // Update the new value of the token_UUID in the database
                user.setTokenUUID(newTokenUUID);
                userRepo.save(user);

                log.debug("!User token_uuid updated successfully, token_uuid={}", user.getTokenUUID());
                return true;

            } else if (currentTokenUUID.equals(tokenUUID)) {

                if (jwtTokenProvider.validateRefreshToken(newRefreshToken, user)) {
                    // Update the new value of the token_uuid in the database
                    user.setTokenUUID(newTokenUUID);
                    userRepo.save(user);

                    log.debug("!User token_uuid updated successfully, token_uuid={}", user.getTokenUUID());
                    return true;

                } else {

                    log.error("!User refresh token invalid, newRefreshToken={}", newRefreshToken);
                }

            } else {

                log.error("!User refresh token UUID is not equals, currentTokenUUID={}, newTokenUUID={}",
                        currentTokenUUID, newTokenUUID);
            }

        } catch (Exception ex) {

            log.error("!User token_uuid is not updated");
        }

        return false;
    }

    private void updateRefreshTokenInDatabase(User user, String tokenUUID) {

        try {
            user.setTokenUUID(tokenUUID);
            userRepo.save(user);

            log.debug("!User token_uuid updated successfully, token_uuid={}", user.getTokenUUID());

        } catch (Exception ex) {

            log.error("!User token_uuid is not updated");
        }
    }

}
