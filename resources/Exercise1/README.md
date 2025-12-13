Relavant source code: ../../frontend-app

## Running the application (with OpenJDK keycloak dev)

## Pre-requisites
* Java 17 or later
* Maven 3.6+
* Self generated public and private key
* Running Keycloak server

### Run client application
1. Move to  `frontend-app` directory.
2. Create `ssh` directory and place RSA key/value.
3. Start the Spring boot application with `mvn spring-boot:run`
4. In the browser, navigate to http://localhsot:8081
