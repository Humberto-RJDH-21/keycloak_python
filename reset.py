# Imports
import os
from keycloak import KeycloakOpenID
from keycloak import KeycloakAdmin
from keycloak import exceptions

# Keycloak credentials
keycloak_username = os.environ.get('KEYCLOAK_USERNAME','USERNAME')
keycloak_password = os.environ.get('KEYCLOAK_PASSWORD','PASSWORD')
keycloak_url = "http://keycloak:port/auth/"
keycloak_realm = "AMIS"
clientId = os.environ.get('CLIENT_ID','SEGU_AMIS')
clientSecret = os.environ.get('CLIENT_SECRET','XXXX')
user_id_keycloak = "XX"
newPassword = "P455w0rd.2020"

# Configure client
keycloak_openid = KeycloakOpenID(server_url=keycloak_url,
                                 client_id=clientId,
                                 realm_name=keycloak_realm,
                                 client_secret_key=clientSecret)

# USERS EMAIL
users = ["vekora7520@mailart.ws"]

# Configure Client
keycloak_admin = KeycloakAdmin(
    server_url=keycloak_url,
    username=keycloak_username,
    password=keycloak_password,
    realm_name=keycloak_realm,
    verify=True)

# Remove Required Actions
def removeRequiredAcions(userid):
    response=keycloak_admin.update_user(user_id=userid, payload={'requiredActions':[]})
    return response

# Reset Password for Users
def reset_password():
    for user in users:
        print(f"Actualizando contraseña para: {user}")
        # Get user ID from name
        user_id_keycloak = keycloak_admin.get_user_id(user)
        if user_id_keycloak:
            # Update User
            try:
                response = removeRequiredAcions(user_id_keycloak)
                response = keycloak_admin.set_user_password(
                    user_id=user_id_keycloak, password="Amis.e2019$", temporary=False)
                print("Ok")
            except exceptions.KeycloakGetError as err:
                if err.response_code==400:
                    print("Contraseña no válida: no debe ser igual a ninguna de las últimas 10 contraseñas.")
                else:
                    print(err.error_message)
        else:
            print("No se encontró el usuario", user)


reset_password()

