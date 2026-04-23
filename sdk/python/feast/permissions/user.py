import logging
from typing import Optional

logger = logging.getLogger(__name__)


class User:
    _username: str
    _roles: Optional[list[str]]
    _groups: Optional[list[str]]
    _namespaces: Optional[list[str]]
    _cur_group: Optional[str]   # 👈 新增

    def __init__(
        self,
        username: str,
        roles: Optional[list[str]] = None,
        groups: Optional[list[str]] = None,
        namespaces: Optional[list[str]] = None,
        cur_group: Optional[str] = None,
    ):
        self._username = username
        self._roles = roles if roles is not None else []
        self._groups = groups if groups is not None else []
        self._namespaces = namespaces if namespaces is not None else []
        self._cur_group = cur_group

    @property
    def username(self):
        return self._username

    @property
    def roles(self):
        return self._roles

    @property
    def groups(self):
        return self._groups

    @property
    def namespaces(self):
        return self._namespaces

    @property
    def cur_group(self):   # 👈 新增 getter
        return self._cur_group

    @cur_group.setter       # 👈 可选：允许修改
    def cur_group(self, value: str):
        self._cur_group = value

    def has_matching_role(self, requested_roles: list[str]) -> bool:
        logger.debug(
            f"Check {self.username} has all {requested_roles}: currently {self.roles}"
        )
        return any(role in self.roles for role in requested_roles)

    def has_matching_group(self, requested_groups: list[str]) -> bool:
        logger.debug(
            f"Check {self.username} has all {requested_groups}: currently {self.groups}"
        )
        return any(group in self.groups for group in requested_groups)

    def has_matching_namespace(self, requested_namespaces: list[str]) -> bool:
        logger.debug(
            f"Check {self.username} has all {requested_namespaces}: currently {self.namespaces}"
        )
        return any(namespace in self.namespaces for namespace in requested_namespaces)

    def __str__(self):
        return (
            f"{self.username} (roles: {self.roles}, groups: {self.groups}, "
            f"cur_group: {self.cur_group}, namespaces: {self.namespaces})"
        )