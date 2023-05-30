package uk.gov.companieshouse.idvoidcpoc.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import uk.gov.companieshouse.idvoidcpoc.dao.Oauth2AuthorisationsDao;
import uk.gov.companieshouse.idvoidcpoc.dao.UsersDao;

@Repository
public interface OauthRepository extends MongoRepository<Oauth2AuthorisationsDao, String> {
}