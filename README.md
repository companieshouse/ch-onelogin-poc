# IDAM OneLogin integration POC

## Description

This is a poc for the integration with OneLogin and replacing small parts of the account service.

Documentation related to this integration can be found at https://www.sign-in.service.gov.uk/documentation. The 
service fundamentally follows this flow: https://docs.sign-in.service.gov.uk/how-gov-uk-one-login-works/#understand-the-technical-flow-gov-uk-one-login-uses
## Running the App
You will need to replace the placeholders in the application.properties file. The client_id and private key can 
be obtained from Paul Forsyth, Chris Morgan or Dale Bradley. The journey.level property should be set to 'result' if no redirect is required.

Then run as a standard Spring application and navigate to http://localhost:3001 in your browser.