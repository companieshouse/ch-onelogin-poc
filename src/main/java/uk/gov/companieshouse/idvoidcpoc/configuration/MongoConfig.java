package uk.gov.companieshouse.idvoidcpoc.configuration;

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.convert.MappingMongoConverter;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

import javax.validation.constraints.NotNull;
import java.util.Objects;

@Configuration
@EnableMongoRepositories(basePackages = "uk.gov.companieshouse.idvoidcpoc.repository")
@Profile("default")
public class MongoConfig {

    private static final String MONGO_DB_URI_PROPERTY = "spring.data.mongodb.uri";
    private static final String MONGO_DB_NAME_PROPERTY = "account.mongodb.dbname";

    @Bean
    public MongoTemplate mongoTemplate(@NotNull Environment environment) {
        String mongoDbName = environment.getProperty(MONGO_DB_NAME_PROPERTY);
        var mongoTemplate = new MongoTemplate(mongoClient(environment), Objects.requireNonNull(mongoDbName));
        MappingMongoConverter converter = (MappingMongoConverter) mongoTemplate.getConverter();
        converter.afterPropertiesSet();
        return mongoTemplate;
    }

    private MongoClient mongoClient(@NotNull Environment environment) {
        String mongoDbUri = environment.getProperty(MONGO_DB_URI_PROPERTY);
        final var connectionString = new ConnectionString(Objects.requireNonNull(mongoDbUri));
        final var mongoClientSettings = MongoClientSettings.builder().applyConnectionString(connectionString).build();
        return MongoClients.create(mongoClientSettings);
    }
}
