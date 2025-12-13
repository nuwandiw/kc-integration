## Set up with OpenJDK keycloak dev

## Pre-requisites
* Java 17 or later
* Maven 3.6+

### Start kc server
1. Download and unpack Keycloak ([Documentation](https://www.keycloak.org/getting-started/getting-started-zip))
2. Copy the content of `resources/certs/` into `keycloak-{version}/certs`
3. Copy `resources/IBM-realm.json` into `keycloak-{version}/exports`
4. Run ```bin/kc.[sh|bat] import --dir exports``` from the `keycloak-{version}` directory.
5. Copy `resources/Exercise2/sq-authenticator.jar` into `keycloak-{version}/providers`
6. Run ```bin/kc.[sh|bat] start-dev --https-certificate-file=certs/cert.pem --https-certificate-key-file=certs/unencrypted_key.pem --http-enabled=true --hostname=kc.idp.com```
