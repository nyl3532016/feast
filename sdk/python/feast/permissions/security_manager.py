import logging
import os
from contextvars import ContextVar
from typing import Callable, List, Optional, Union

from feast.errors import (
    FeastGroupMismatchError,
    FeastObjectNotFoundException,
    FeastPermissionError,
)
from feast.feast_object import FeastObject
from feast.infra.registry.base_registry import BaseRegistry
from feast.permissions.action import AuthzedAction
from feast.permissions.enforcer import enforce_policy
from feast.permissions.permission import Permission
from feast.permissions.user import User
from feast.project import Project

logger = logging.getLogger(__name__)


def _check_group_match(
    user: Optional[User],
    resources: list[FeastObject],
    registry: Optional[BaseRegistry] = None,
    project: Optional[str] = None,
) -> None:
    """
    检查用户是否有权访问资源的 group。
    - 如果传入了 project 参数，直接查 project 的 group 进行校验
    - 如果没有 project 参数但资源有 group 属性（如 Project），直接比较

    Args:
        user: 当前用户
        resources: 要检查的资源列表
        registry: Registry 实例，用于获取 project 的 group
        project: 项目名称，用于获取 project 的 group,来自客户端配置文件

    Raises:
        FeastGroupMismatchError: 如果用户 group 与资源 group 不匹配
        FeastPermissionError: 如果没有 user 或 user.cur_group
    """
    # 检查必须有 user
    if not user:
        raise FeastPermissionError("Authentication required: no user context found")

    # 检查必须有 cur_group
    if not user.cur_group:
        raise FeastPermissionError(
            f"Authentication required: user '{user.username}' has no group assigned"
        )

    # 优先通过 project 参数获取 group（适用于 Entity、FeatureView 等资源）
    if project and registry is not None:
        try:
            # 权限检查不使用缓存，获取最新 project 数据
            project_obj = registry.get_project(name=project, allow_cache=False)
            if project_obj:
                if not project_obj.group:
                    raise FeastPermissionError(
                        f"Project '{project}' has no group assigned. "
                        f"Please configure the 'group' attribute for this project."
                    )
                if project_obj.group != user.cur_group:
                    raise FeastGroupMismatchError(
                        user_group=user.cur_group,
                        resource_group=project_obj.group,
                        resource=f"project:{project}"
                    )
                logger.info(f"The project's group in the current configuration is: {project_obj.group}, and the user's DACP group is: {user.cur_group}")
                return  # 校验通过
            else:
                raise FeastPermissionError(f"Project '{project}' not found in registry")
        except Exception:
            logger.error(f"Failed to get project {project} for group check")
            raise


class SecurityManager:
    """
    The security manager it's the entry point to validate the configuration of the current user against the configured permission policies.
    It is accessed and defined using the global functions `get_security_manager` and `set_security_manager`
    """

    def __init__(
        self,
        project: str,
        registry: BaseRegistry,
    ):
        self._project = project
        self._registry = registry
        self._current_user: ContextVar[Optional[User]] = ContextVar(
            "current_user", default=None
        )

    def set_current_user(self, current_user: User):
        """
        Init the user for the current context.
        """
        self._current_user.set(current_user)

    @property
    def current_user(self) -> Optional[User]:
        """
        Returns:
            str: the possibly empty instance of the current user. `contextvars` module is used to ensure that each concurrent request has its own
            individual user.
        """
        return self._current_user.get()

    @property
    def permissions(self) -> list[Permission]:
        """
        Returns:
            list[Permission]: the list of `Permission` configured in the Feast registry.
        """
        return self._registry.list_permissions(project=self._project)

    def get_permissions_for_project(self, project: str) -> list[Permission]:
        """
        Get permissions for a specific project.

        Args:
            project: The project name to get permissions for.

        Returns:
            list[Permission]: the list of `Permission` for the given project.
        """
        logger.debug(f"get_permissions_for_project project = {project}")
        return self._registry.list_permissions(project=project)

    def assert_permissions(
        self,
        resources: list[FeastObject],
        actions: Union[AuthzedAction, List[AuthzedAction]],
        filter_only: bool = False,
        project: Optional[str] = None,
    ) -> list[FeastObject]:
        """
        Verify if the current user is authorized to execute the requested actions on the given resources.

        If no permissions are defined, the result is to deny the execution.

        Args:
            resources: The resources for which we need to enforce authorized permission.
            actions: The requested actions to be authorized.
            filter_only: If `True`, it removes unauthorized resources from the returned value, otherwise it raises a `FeastPermissionError` the
            first unauthorized resource. Defaults to `False`.
            project: The project to get permissions from. If None, uses the default project. Defaults to `None`.

        Returns:
            list[FeastObject]: A filtered list of the permitted resources, possibly empty.

        Raises:
            FeastPermissionError: If the current user is not authorized to execute all the requested actions on the given resources.
            FeastGroupMismatchError: If the user's group does not match the resource's group.
        """
        logger.info(f"assert_permissions cur project = {project}, user = {self.current_user}")

        # 新增：Group 匹配检查
        _check_group_match(self.current_user, resources, self._registry, project)


        return enforce_policy(
            permissions=self.get_permissions_for_project(project),
            user=self.current_user if self.current_user is not None else User("", []),
            resources=resources,
            actions=actions if isinstance(actions, list) else [actions],
            filter_only=filter_only,
        )


def assert_permissions_to_update(
    resource: FeastObject,
    getter: Union[
        Callable[[str, str, bool], FeastObject], Callable[[str, bool], FeastObject]
    ],
    project: str,
    allow_cache: bool = True,
) -> FeastObject:
    """
    Verify if the current user is authorized to create or update the given resource.
    If the resource already exists, the user must be granted permission to execute DESCRIBE and UPDATE actions.
    If the resource does not exist, the user must be granted permission to execute the CREATE action.

    If no permissions are defined, the result is to deny the execution.

    Args:
        resource: The resources for which we need to enforce authorized permission.
        getter: The getter function used to retrieve the existing resource instance by name.
        The signature must be `get_permission(self, name: str, project: str, allow_cache: bool)`
        project: The project nane used in the getter function.
        allow_cache: Whether to use cached data. Defaults to `True`.
    Returns:
        FeastObject: The original `resource`, if permitted.

    Raises:
        FeastPermissionError: If the current user is not authorized to execute all the requested actions on the given resource or on the existing one.
        FeastGroupMismatchError: If the user's group does not match the resource's group.
    """
    sm = get_security_manager()
    if not is_auth_necessary(sm):
        return resource

    # 新增：Group 匹配检查（对新资源）
    _check_group_match(sm.current_user, [resource], sm._registry, project)

    actions = [AuthzedAction.DESCRIBE, AuthzedAction.UPDATE]
    try:
        if isinstance(resource, Project):
            existing_resource = getter(
                name=resource.name,
                allow_cache=allow_cache,
            )  # type: ignore[call-arg]
        else:
            existing_resource = getter(
                name=resource.name,
                project=project,
                allow_cache=allow_cache,
            )  # type: ignore[call-arg]
        assert_permissions(resource=existing_resource, actions=actions, project=project)
    except FeastObjectNotFoundException:
        actions = [AuthzedAction.CREATE]
    resource_to_update = assert_permissions(resource=resource, actions=actions, project=project)
    return resource_to_update


def assert_permissions(
    resource: FeastObject,
    actions: Union[AuthzedAction, List[AuthzedAction]],
    project: Optional[str] = None,
) -> FeastObject:
    """
    A utility function to invoke the `assert_permissions` method on the global security manager.

    If no global `SecurityManager` is defined, the execution is permitted.

    Args:
        resource: The resource for which we need to enforce authorized permission.
        actions: The requested actions to be authorized.
        project: The project to get permissions from. If None, uses the default project. Defaults to `None`.
    Returns:
        FeastObject: The original `resource`, if permitted.

    Raises:
        FeastPermissionError: If the current user is not authorized to execute the requested actions on the given resources.
        FeastGroupMismatchError: If the user's group does not match the resource's group.
    """
    logger.info(f"assert_permissions cur project = {project}")

    sm = get_security_manager()
    if not is_auth_necessary(sm):
        return resource

    return sm.assert_permissions(  # type: ignore[union-attr]
        resources=[resource], actions=actions, filter_only=False, project=project
    )[0]


def permitted_resources(
    resources: list[FeastObject],
    actions: Union[AuthzedAction, List[AuthzedAction]],
    project: Optional[str] = None,
) -> list[FeastObject]:
    """
    A utility function to invoke the `assert_permissions` method on the global security manager.

    If no global `SecurityManager` is defined (NoAuthConfig), all resources are permitted.
    If a SecurityManager exists but no user context and actions are requested, deny access for security.
    If a SecurityManager exists but user is intra-communication, allow access.

    Args:
        resources: The resources for which we need to enforce authorized permission.
        actions: The requested actions to be authorized.
        project: The project to get permissions from. If None, uses the default project. Defaults to `None`.
    Returns:
        list[FeastObject]]: A filtered list of the permitted resources, possibly empty.

    Raises:
        FeastGroupMismatchError: If the user's group does not match any resource's group.
    """
    logger.info(f"permitted_resources cur project = {project}")
    sm = get_security_manager()
    if not is_auth_necessary(sm):
        # Check if this is NoAuthConfig (no security manager) vs missing user context vs intra-communication
        if sm is None:
            # NoAuthConfig: allow all resources
            logger.debug("NoAuthConfig enabled - allowing access to all resources")
            return resources
        elif sm.current_user is not None:
            # Intra-communication user: allow all resources
            logger.debug("Intra-communication user - allowing access to all resources")
            return resources
        else:
            # Security manager exists but no user context - deny access for security
            logger.warning(
                "Security manager exists but no user context - denying access to all resources"
            )
            return []

    return sm.assert_permissions(resources=resources, actions=actions, filter_only=True, project=project)  # type: ignore[union-attr]


"""
The possibly empty global instance of `SecurityManager`.
"""
_sm: Optional[SecurityManager] = None


def get_security_manager() -> Optional[SecurityManager]:
    """
    Return the global instance of `SecurityManager`.
    """
    global _sm
    return _sm


def set_security_manager(sm: SecurityManager):
    """
    Initialize the global instance of `SecurityManager`.
    """

    global _sm
    _sm = sm


def no_security_manager():
    """
    Initialize the empty global instance of `SecurityManager`.
    """

    global _sm
    _sm = None


def is_auth_necessary(sm: Optional[SecurityManager]) -> bool:
    intra_communication_base64 = os.getenv("INTRA_COMMUNICATION_BASE64")

    # If no security manager, no auth is necessary
    if sm is None:
        return False

    # If security manager exists but no user context, auth is necessary (security-first approach)
    if sm.current_user is None:
        return True

    # If user is intra-communication, no auth is necessary
    if sm.current_user.username == intra_communication_base64:
        return False

    # Otherwise, auth is necessary
    return True
