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

    public String getForename() {
        return forename;
    }

    public void setForename(String forename) {
        this.forename = forename;
    }

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }

    public String getUserID() {
        return userID;
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
