package uk.gov.companieshouse.idvoidcpoc.dao;

import org.springframework.data.mongodb.core.mapping.Field;

public class UserDetailsDao {
    @Field("forename")
    private String forename;

    @Field("surname")
    private String surname;

    @Field("user_id")
    private String userID;

    @Field("email")
    private String email;
}
