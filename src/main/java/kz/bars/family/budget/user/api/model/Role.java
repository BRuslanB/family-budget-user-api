package kz.bars.family.budget.user.api.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

@Entity
@Getter
@Setter
public class Role extends BaseEntity implements GrantedAuthority {

    @Column(nullable = false)
    private String name;
    @Column(nullable = false)
    private String role;
    @Override
    public String getAuthority() {
        return role;
    }

}
