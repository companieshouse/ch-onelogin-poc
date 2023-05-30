package uk.gov.companieshouse.idvoidcpoc;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@SpringBootApplication
public class OneLoginPOCApplication implements WebMvcConfigurer {
    public static void main(String[] args) {
        SpringApplication.run(OneLoginPOCApplication.class, args);
    }
}