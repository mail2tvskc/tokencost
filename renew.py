import os
import sys
import time
import base64
import logging
import requests
import boto3
import argparse
import csv
import datetime
from botocore.exceptions import ClientError
from databricks.sdk import WorkspaceClient
from databricks.sdk.errors.platform import ResourceDoesNotExist
from databricks.sdk.service import catalog as databricks_catalog
from databricks.sdk.service import catalog
from databricks.sdk.errors import NotFound

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser(description="Refresh Okta OAuth tokens for SCIM group members.")
parser.add_argument('--env', required=True, help='Environment code like dev, tst, prd')
parser.add_argument('--group', required=True, help='SCIM group name override')

args = parser.parse_args()
ENV = args.env.lower()
group_name = args.group

sf_env_config = {
    'dev':  {'sf_env': 'dev', 'sf_url': 'cms-onepinp.privatelink.snowflakecomputing.com'},
    'test': {'sf_env': 'tst', 'sf_url': 'cms-onepinp.privatelink.snowflakecomputing.com'},
    'impl': {'sf_env': 'impl', 'sf_url': 'cms-onepinp.privatelink.snowflakecomputing.com'},
    'prod': {'sf_env': 'prd', 'sf_url': 'cms-onepi.privatelink.snowflakecomputing.com'}
}

sf_host = sf_env_config[ENV]['sf_url']
sf_env = sf_env_config[ENV]['sf_env']


def log_to_csv_file(action: str, status: str, message: str) -> None:
    log_file = "log_entries.csv"
    timestamp = datetime.datetime.utcnow().isoformat()
    try:
        file_exists = os.path.isfile(log_file)
        with open(log_file, mode='a', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=["timestamp", "action", "status", "message"])
            if not file_exists:
                writer.writeheader()
            writer.writerow({
                "timestamp": timestamp,
                "action": action,
                "status": status,
                "message": message
            })
        logger.info(f"ðŸ“ Logged to CSV: {action} - {status}")
    except Exception as e:
        logger.error(f"âŒ Error writing to CSV file: {e}")


def get_user_info(client: WorkspaceClient, user_id: str) -> dict | None:
    try:
        return client.api_client.do("GET", f"/api/2.0/preview/scim/v2/Users/{user_id}")
    except Exception as e:
        logger.error(f"Failed to get user info for {user_id}: {e}")
        return None


def get_ssm_parameter(name: str, with_decryption=True) -> str | None:
    try:
        ssm = boto3.client('ssm')
        response = ssm.get_parameter(Name=name, WithDecryption=with_decryption)
        return response['Parameter']['Value']
    except ClientError as e:
        logger.warning(f"Could not get parameter '{name}': {e.response['Error']['Message']}")
        return None


def load_and_set_env_secrets(env: str) -> None:
    os.environ['DBR_WS_URL'] = f"https://onepi-{env}.cloud.databricks.com"
    parameters = {
        'DBR_SERVICE_PRINCIPLE_client_id': f"/{env}/databricks/databricks_client_id",
        'DBR_SERVICE_PRINCIPLE_client_secret': f"/{env}/databricks/databricks_client_secret",
        'OKTA_SF_CLIENT_ID': f"/{env}/databricks/OKTA_SF_CLIENT_ID",
        'SF_OAUTH_TOKEN_REQUEST_URL': f"/{env}/databricks/SF_OAUTH_TOKEN_REQUEST_URL"
    }

    missing = []
    for key, path in parameters.items():
        value = get_ssm_parameter(path)
        if value:
            os.environ[key] = value
        else:
            missing.append(key)

    if missing:
        logger.error(f"Missing secrets for: {', '.join(missing)}")
        sys.exit(1)
    logger.info("âœ“ All required secrets loaded.")


def validate_env_vars(required: list[str]) -> None:
    missing = [var for var in required if not os.environ.get(var)]
    if missing:
        logger.error(f"Missing environment variables: {', '.join(missing)}")
        sys.exit(1)


def initialize_workspace_client() -> WorkspaceClient:
    return WorkspaceClient(
        host=os.environ["DBR_WS_URL"],
        client_id=os.environ["DBR_SERVICE_PRINCIPLE_client_id"],
        client_secret=os.environ["DBR_SERVICE_PRINCIPLE_client_secret"]
    )


def get_group_id(client: WorkspaceClient, group_name: str) -> str | None:
    try:
        response = client.api_client.do("GET", "/api/2.0/preview/scim/v2/Groups", query={"filter": f'displayName eq "{group_name}"'})
        groups = response.get("Resources", [])
        return groups[0]["id"] if groups else None
    except Exception as e:
        logger.error(f"Failed to get group ID for {group_name}: {e}")
        return None


def get_group_members(client: WorkspaceClient, group_id: str) -> list[dict]:
    try:
        group = client.api_client.do("GET", f"/api/2.0/preview/scim/v2/Groups/{group_id}")
        return group.get("members", [])
    except Exception as e:
        logger.error(f"Failed to fetch group members: {e}")
        return []


def refresh_okta_access_token(client: WorkspaceClient, secret_scope: str, client_id: str, token_url: str):
    try:
        refresh_token_b64 = client.secrets.get_secret(scope=secret_scope, key="refresh_token").value
        refresh_token = base64.b64decode(refresh_token_b64).decode('utf-8')

        response = requests.post(
            token_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "client_id": client_id,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token
            }
        )
        response.raise_for_status()
        tokens = response.json()

        client.secrets.put_secret(scope=secret_scope, key='access_token', string_value=tokens.get('access_token'))
        client.secrets.put_secret(scope=secret_scope, key='id_token', string_value=tokens.get('id_token'))
        client.secrets.put_secret(scope=secret_scope, key='refresh_token', string_value=tokens.get('refresh_token'))

        log_to_csv_file("Refresh Okta Token", "Success", "Tokens refreshed successfully")
        logger.info(f"âœ“ Refreshed tokens for: {secret_scope}")
        return tokens.get('access_token')

    except (base64.binascii.Error, UnicodeDecodeError):
        log_to_csv_file("Refresh Okta Token", "Failure", "Failed to decode refresh token")
        logger.error(f"Failed to decode refresh token in scope: {secret_scope}")
        return None
    except ResourceDoesNotExist:
        log_to_csv_file("Refresh Okta Token", "Failure", "Secret scope does not exist")
        logger.warning(f"Secret scope does not exist: {secret_scope}")
        return None
    except Exception as e:
        log_to_csv_file("Refresh Okta Token", "Failure", f"Error: {e}")
        logger.error(f"Error refreshing token for scope '{secret_scope}': {e}")
        return None

def create_or_update_connection(client, connection_name, user_name, access_token):
    try:
        connection = client.connections.get(name=connection_name)
        logger.info(f"ðŸ” Updating connection: {connection_name}")
        client.connections.update(
            name=connection_name,
            options={
                "host": sf_host,
                "port": "443",
                "sfWarehouse": f"OPI_{sf_env}_DBR_WH",
                "user": user_name,
                "access_token": access_token
            }
        )
        logger.info(f"ðŸ” Updated connection: {connection_name}")
        return connection
    except ResourceDoesNotExist:
        logger.info(f"âž• Creating new connection: {connection_name}")
        return client.connections.create(
            name=connection_name,
            connection_type=databricks_catalog.ConnectionType.SNOWFLAKE,
            options={
                "host": sf_host,
                "port": "443",
                "sfWarehouse": f"OPI_{sf_env}_DBR_WH",
                "user": user_name,
                "access_token": access_token
            }
        )
    except Exception as e:
        logger.exception(f"âŒ Failed to create/update connection '{connection_name}': {e}")
        raise


def grant_permissions(client, resource_name, resource_type, principals):
    try:
        changes = [
            catalog.PermissionsChange(
                add=[catalog.Privilege.ALL_PRIVILEGES],
                principal=principal
            ) for principal in principals
        ]
        client.grants.update(
            full_name=resource_name,
            securable_type=resource_type,
            changes=changes
        )
        logger.info(f"ðŸ” Granted ALL_PRIVILEGES on {resource_type.value} '{resource_name}' to {', '.join(principals)}")
    except Exception as e:
        logger.exception(f"âŒ Failed to grant permissions on {resource_type.value} '{resource_name}': {e}")
        raise


def check_catalog_exists(client, catalog_name):
    """Returns True if the catalog exists, False otherwise."""
    try:
        client.catalogs.get(name=catalog_name)
        return True
    except NotFound:
        return False

def create_foreign_catalog(client, catalog_name, connection_name):
    try:
        client.catalogs.create(
            name=catalog_name,
            connection_name=connection_name,
            options={"database": f"adm_{sf_env}"}
        )
    except Exception as e:
        logger.exception(f"âŒ Failed to create catalog '{catalog_name}': {e}")
        raise


def manage_connections_for_active_user(client: WorkspaceClient, user_name: str, access_token: str):
    connection_name = f"{user_name}_SF_{sf_env}"
    catalog_name = f"{user_name}_SF_ADM_{sf_env}"
    admin_group = f"OPI_DBR_ADMIN_{ENV[0].upper()}"

    try:
        connection = create_or_update_connection(client, connection_name, user_name, access_token)
        grant_permissions(client, connection_name, catalog.SecurableType.CONNECTION, [user_name, admin_group])

        catalog_exists = check_catalog_exists(client, catalog_name)
        if not catalog_exists:
            create_foreign_catalog(client, catalog_name, connection_name)
            logger.info(f"ðŸ“ Created catalog: {catalog_name}")
            log_to_csv_file("Create Catalog", "Success", f"Created catalog: {catalog_name}")
        else:
            logger.info(f"ðŸ“ Catalog already exists: {catalog_name}")

        grant_permissions(client, catalog_name, catalog.SecurableType.CATALOG, [user_name, admin_group])
        logger.info(f"âœ… Catalog setup and privileges granted for {catalog_name}")
        log_to_csv_file("Update Connection", "Success", f"Processed connection and catalog for: {user_name}")

    except Exception as e:
        logger.exception(f"âŒ Error managing connection/catalog for user '{user_name}': {e}")
        log_to_csv_file("Update Connection", "Failure", f"Error: {e}")


def process_group_users(client: WorkspaceClient, group_members: list[dict], client_id: str, token_url: str):
    total_users = len(group_members)
    for index, member in enumerate(group_members, start=1):
        if member.get("$ref", "").startswith("Users/"):
            user_id = member["value"]
            user = get_user_info(client, user_id)
            if user:
                user_name = user.get("userName")
                display_name = user.get("displayName")
                scope = f"OAuth_tokens_{user_name}"

                if user.get("active"):
                    logger.info(f"ðŸ‘¨â€ðŸ’» Processing user {index}/{total_users}: {display_name} ({user_name})")
                    access_token = refresh_okta_access_token(client, scope, client_id, token_url)
                    time.sleep(0.5)
                    if access_token:
                        manage_connections_for_active_user(client, user_name, access_token)
                else:
                    logger.info(f"â¸ Skipping inactive user {index}/{total_users}: {display_name} ({user_name})")


def main():
    env = ENV
    if not env:
        logger.error("ENV is not set.")
        sys.exit(1)

    load_and_set_env_secrets(env)
    validate_env_vars([
        "DBR_WS_URL", "DBR_SERVICE_PRINCIPLE_client_id",
        "DBR_SERVICE_PRINCIPLE_client_secret", "OKTA_SF_CLIENT_ID",
        "SF_OAUTH_TOKEN_REQUEST_URL"
    ])

    client = initialize_workspace_client()
    group_id = get_group_id(client, group_name)

    if not group_id:
        logger.error(f"No SCIM group found with name: {group_name}")
        sys.exit(1)

    logger.info(f"ðŸŽ¯ Found group: {group_name}, ID: {group_id}")
    group_members = get_group_members(client, group_id)

    if not group_members:
        logger.warning("No group members found.")
        return

    process_group_users(client, group_members, os.environ["OKTA_SF_CLIENT_ID"], os.environ["SF_OAUTH_TOKEN_REQUEST_URL"])


if __name__ == "__main__":
    main()

