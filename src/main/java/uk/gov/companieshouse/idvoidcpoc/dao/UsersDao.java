package uk.gov.companieshouse.idvoidcpoc.dao;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.time.LocalDate;

@Document(collection = "users")
public class UsersDao {
    @Id
    private String id;

    @Field("email")
    private String email;

    @Field("locale")
    private String locale;

    @Field("password")
    private String password;

    @Field("created")
    private LocalDate created;

    @Field("one_login")
    private boolean oneLogin;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getLocale() {
        return locale;
    }

    public void setLocale(String locale) {
        this.locale = locale;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public LocalDate getCreated() {
        return created;
    }

    public void setCreated(LocalDate created) {
        this.created = created;
    }

    public boolean isOneLogin() {
        return oneLogin;
    }

    public void setOneLogin(boolean oneLogin) {
        this.oneLogin = oneLogin;
    }
}
