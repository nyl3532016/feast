import logging
from typing import Optional

import jwt
from starlette.authentication import AuthenticationError

from feast.permissions.auth.token_parser import TokenParser
from feast.permissions.user import User
import os
logger = logging.getLogger(__name__)


class DacpTokenParser(TokenParser):
    """
    DACP Token Parser for server-side JWT validation.

    Parses unsigned JWT tokens with the following payload:
    {
        "group": "data_team",
        "role": "admin",
        "account": "admin",
        "iss": "dacp",
        "iat": 1234567890
    }
    """

    def __init__(self):
        self.SECRET = os.getenv("JWT_SECRET", "123456789")


    async def user_details_from_access_token(self, access_token: str) -> User:
        """
        Validate the DACP access token and extract user details.

        Returns:
            User: Current user with associated roles.

        Raises:
            AuthenticationError if token is invalid.
        """
        # 1. 检查 token 是否为空
        if not access_token:
            raise AuthenticationError("JWT_TOKEN_EMPTY: Missing authentication token")

        try:
            # DACP tokens are unsigned (issued by client from env vars)
            data = jwt.decode(
                access_token,
                self.SECRET,
                algorithms=["HS256"],
            )
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("JWT_TOKEN_EXPIRED: Token has expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"JWT_TOKEN_INVALID: {str(e)}")
        except Exception as e:
            raise AuthenticationError(f"JWT_DECODE_ERROR: {str(e)}")

        # Build roles from claims
        roles = []

        # Add group as role
        group = data.get("group")
        account = data.get("account")
        role = data.get("role")

        # 验证必需字段
        if not account:
            raise AuthenticationError("JWT_NO_ACCOUNT: No account found in token payload")
        if not group:
            raise AuthenticationError("JWT_NO_GROUP: No group found in token payload")
        if not role:
            raise AuthenticationError("JWT_NO_ROLE: No role found in token payload")

        roles.append(role)

        logger.info(f"DACP authenticated user: {account}, roles: {roles}, cur_group:{group}")

        return User(username=account, roles=roles, cur_group=group)
