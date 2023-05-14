package kz.bars.family.budget.user.api.actuator.health;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

@Component
public class MyHealthIndicator implements HealthIndicator {

    final DataSource dataSource;

    public MyHealthIndicator(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public Health health() {
        int errorCode = check();
        if (errorCode != 0) {
            return Health.down().withDetail("Error Code", errorCode).build();
        }
        return Health.up().build();
    }

    private int check() {
        try {
            // Try to connect to the database
            Connection connection = dataSource.getConnection();
            Statement statement = connection.createStatement();
            statement.executeQuery("SELECT 1");
            statement.close();
            connection.close();
            return 0;
        } catch (SQLException e) {
            // If there is an exception, return an error code
            return 1;
        }
    }

}
