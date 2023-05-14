package kz.bars.family.budget.user.api.actuator.info;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.info.Info.Builder;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.stereotype.Component;

@Component
public class MyInfoContributor implements InfoContributor {

    final OpenAPI openAPI;

    @Autowired
    public MyInfoContributor(OpenAPI openAPI) {
        this.openAPI = openAPI;
    }

    @Override
    public void contribute(Builder builder) {
        Info info = openAPI.getInfo();
        builder.withDetail("title", info.getTitle());
        builder.withDetail("description", info.getDescription());
        builder.withDetail("version", info.getVersion());
        builder.withDetail("author", info.getContact().getName());
        builder.withDetail("email", info.getContact().getEmail());
    }
}
