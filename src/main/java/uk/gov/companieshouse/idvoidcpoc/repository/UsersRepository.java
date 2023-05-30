package uk.gov.companieshouse.idvoidcpoc.repository;

        import org.springframework.data.mongodb.repository.MongoRepository;
        import org.springframework.stereotype.Repository;
        import uk.gov.companieshouse.idvoidcpoc.dao.UsersDao;

        import java.util.List;

@Repository
public interface UsersRepository extends MongoRepository<UsersDao, String> {

       List<UsersDao> findByEmail(String email);

}
