package com.example.vulnerable.repository;

import jakarta.persistence.EntityManager;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.springframework.stereotype.Repository;

@Repository
public class VulnerableUserRepository {

    private final EntityManager entityManager;
    private final DataSource dataSource;

    public VulnerableUserRepository(EntityManager entityManager, DataSource dataSource) {
        this.entityManager = entityManager;
        this.dataSource = dataSource;
    }

    public List<?> searchByNameNativeQuery(String name) {
        String sql = "select * from users where name = '" + name + "'";
        return entityManager.createNativeQuery(sql).getResultList();
    }

    public List<String> searchByRawStatement(String name) {
        List<String> results = new ArrayList<>();
        String sql = "select name from users where name = '" + name + "'";

        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            while (resultSet.next()) {
                results.add(resultSet.getString("name"));
            }
        } catch (Exception ignored) {
            // Demo-only vulnerable sample code.
        }

        return results;
    }
}
