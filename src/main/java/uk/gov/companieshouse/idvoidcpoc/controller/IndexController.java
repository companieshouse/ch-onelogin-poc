package uk.gov.companieshouse.idvoidcpoc.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@Controller
public class IndexController {
    protected static final String INDEX_VIEW = "home";
    protected static final String ERROR_VIEW = "error";


    @GetMapping("/poc")
    public String index(Model model,
                                    HttpServletRequest request) {
        return INDEX_VIEW;
    }
}

