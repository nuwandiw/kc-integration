Relavant source code: ../../authenticator-extension

## Running the extension (with OpenJDK keycloak dev)

## Pre-requisites
* Running Keycloaks erver


### Steps to test
1. Navigate to https://kc.idp.com:8443/realms/IBM/account and follow user registration flow. Keycloak should ask you to pick a security question and answer.
2. Register a OTP authenticator for the newly created user.
3. In a private window login to https://kc.idp.com:8443/realms/IBM/account as the new user. It should let you pass only after providing the answer to the security question or after providing OTP
