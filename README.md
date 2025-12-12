## Running the application (with OpenJDK keycloak dev)

## Pre-requisites
* Java 17 or later
* Maven 3.6+
* Self generated public and private key

### Start kc server
1. Download and unpack Keycloak ([Documentation](https://www.keycloak.org/getting-started/getting-started-zip))
2. Copy the content of `resources/certs/` into `keycloak-{version}/certs`
3. Copy `resources/IBM-realm.json` into `keycloak-{version}/exports`
4. Run ```bin/kc.[sh|bat] import --dir exports``` from the `keycloak-{version}` directory.
5. Run ```bin/kc.[sh|bat] start-dev --https-certificate-file=certs/cert.pem --https-certificate-key-file=certs/unencrypted_key.pem --http-enabled=true --hostname=kc.idp.com```

### Run client application
1. Move to  `frontend-app` directory.
2. Create `ssh` directory and place RSA key/value.
3. Start the Spring boot application with `mvn spring-boot:run`
4. In the browser, navigate to http://locahsot:8081
