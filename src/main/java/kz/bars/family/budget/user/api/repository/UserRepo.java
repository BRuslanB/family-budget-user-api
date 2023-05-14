package kz.bars.family.budget.user.api.repository;

import kz.bars.family.budget.user.api.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
public interface UserRepo extends JpaRepository<User, Long> {
    User findByEmail(String email);

}
