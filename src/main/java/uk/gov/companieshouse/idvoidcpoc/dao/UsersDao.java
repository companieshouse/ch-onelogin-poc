package uk.gov.companieshouse.idvoidcpoc.dao;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.time.LocalDateTime;

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
    private LocalDateTime created;

    @Field("one_login_data")
    private OneLoginDataDao oneLoginData;

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

    public LocalDateTime getCreated() {
        return created;
    }

    public void setCreated(LocalDateTime created) {
        this.created = created;
    }

    public OneLoginDataDao getOneLoginData() {
        return oneLoginData;
    }

    public void setOneLoginData(OneLoginDataDao oneLoginData) {
        this.oneLoginData = oneLoginData;
    }
}
