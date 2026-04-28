import asyncio
import logging

import grpc
from starlette.authentication import AuthenticationError

from feast.permissions.auth.auth_manager import (
    get_auth_manager,
)
from feast.permissions.security_manager import get_security_manager

logger = logging.getLogger(__name__)


class AuthInterceptor(grpc.ServerInterceptor):
    def intercept_service(self, continuation, handler_call_details):
        sm = get_security_manager()

        if sm is not None:
            auth_manager = get_auth_manager()
            try:
                access_token = auth_manager.token_extractor.extract_access_token(
                    metadata=dict(handler_call_details.invocation_metadata)
                )

                logger.debug(
                    f"Fetching user details for token of length: {len(access_token)}"
                )
                current_user = asyncio.run(
                    auth_manager.token_parser.user_details_from_access_token(access_token)
                )
                logger.debug(f"User is: {current_user}")
                sm.set_current_user(current_user)
            except AuthenticationError as e:
                # 认证错误，转换为 gRPC 格式
                error_msg = str(e)
                logger.warning(f"Authentication failed: {error_msg}")
                return self._abort_handler(grpc.StatusCode.UNAUTHENTICATED, error_msg)
            except RuntimeError as e:
                # 运行时错误（如缺少环境变量）
                error_msg = str(e)
                logger.error(f"Authentication runtime error: {error_msg}")
                return self._abort_handler(grpc.StatusCode.INTERNAL, error_msg)
            except Exception as e:
                # 其他未知错误
                error_msg = str(e)
                logger.exception(f"Unexpected authentication error: {error_msg}")
                return self._abort_handler(grpc.StatusCode.INTERNAL, f"JWT_INTERNAL_ERROR: {error_msg}")

        return continuation(handler_call_details)

    def _abort_handler(self, code: grpc.StatusCode, details: str):
        """返回一个会立即终止请求的 handler"""
        def abort_handler(request, context):
            context.abort(code, details)

        return grpc.unary_unary_rpc_method_handler(abort_handler)
