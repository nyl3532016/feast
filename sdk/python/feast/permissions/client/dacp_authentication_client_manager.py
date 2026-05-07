import logging
import os
from datetime import datetime, timezone

import jwt

from feast.permissions.auth_model import DacpAuthConfig
from feast.permissions.client.auth_client_manager import AuthenticationClientManager

logger = logging.getLogger(__name__)


class DacpAuthClientManager(AuthenticationClientManager):
    """
    DACP authentication ui_server manager.

    Generates JWT tokens from environment variables:
    - DACP_USER_NAME: User name (account claim)
    - DACP_GROUP_NAME: Group name (group claim)
    - DACP_ROLE: Role (role claim)
    """

    def __init__(self, auth_config: DacpAuthConfig):
        self.auth_config = auth_config
        logger.debug(f"DacpAuthClientManager initialized with config: {auth_config}")

    def get_token(self) -> str:
        """
        Generate JWT token from DACP environment variables.

        Returns:
            JWT token string

        Raises:
            RuntimeError: If required environment variables are not set
        """
        # Get environment variable names from config
        user_name_env = self.auth_config.user_name_env or "DACP_USER_NAME"
        group_name_env = self.auth_config.group_name_env or "DACP_GROUP_NAME"
        role_env = self.auth_config.role_env or "DACP_ROLE"

        # Read environment variables
        user_name = os.getenv(user_name_env)
        group_name = os.getenv(group_name_env)
        role = os.getenv(role_env)

        jwt_secret = os.getenv("JWT_SECRET", "123456789")

        # Validate required environment variables
        if not user_name:
            raise RuntimeError(
                f"DACP authentication requires {user_name_env} environment variable to be set"
            )
        if not group_name:
            raise RuntimeError(
                f"DACP authentication requires {group_name_env} environment variable to be set"
            )
        if not role:
            raise RuntimeError(
                f"DACP authentication requires {role_env} environment variable to be set"
            )

        # Build JWT payload
        payload = {
            "account": user_name,
            "group": group_name,
            "role": role,
            "iat": datetime.now(timezone.utc),
        }

        # Generate JWT with secret
        token = jwt.encode(payload, jwt_secret, algorithm="HS256")

        logger.debug(
            f"Generated DACP JWT token for user: {user_name}, group: {group_name}, role: {role}"
        )
        return token
