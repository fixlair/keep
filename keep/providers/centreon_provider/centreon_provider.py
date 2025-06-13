"""
Centreon is a class that provides a set of methods to interact with the Centreon API.
"""

import dataclasses
import datetime
import typing

import pydantic
import requests

from keep.api.models.alert import AlertDto, AlertSeverity, AlertStatus
from keep.contextmanager.contextmanager import ContextManager
from keep.exceptions.provider_exception import ProviderException
from keep.providers.base.base_provider import BaseProvider
from keep.providers.models.provider_config import ProviderConfig, ProviderScope
from keep.providers.models.provider_method import ProviderMethod


@pydantic.dataclasses.dataclass
class CentreonProviderAuthConfig:
    """
    CentreonProviderAuthConfig is a class that holds the authentication information for the CentreonProvider.
    """

    host_url: pydantic.AnyHttpUrl = dataclasses.field(
        metadata={
            "required": True,
            "description": "Centreon Host URL",
            "sensitive": False,
            "validation": "any_http_url",
        },
    )

    username: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Centreon username",
            "sensitive": False,
        },
    )

    password: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Centreon password",
            "sensitive": True,
        },
    )


class CentreonProvider(BaseProvider):
    PROVIDER_DISPLAY_NAME = "Centreon"
    PROVIDER_TAGS = ["alert"]
    PROVIDER_CATEGORY = ["Monitoring"]
    PROVIDER_SCOPES = [
        ProviderScope(name="authenticated", description="User is authenticated"),
    ]

    PROVIDER_METHODS = [
        ProviderMethod(
            name="Acknowledge alert",
            func_name="acknowledge_alert",
            scopes=["authenticated"],
            type="action",
        ),
        ProviderMethod(
            name="Get alert status",
            func_name="get_alert_status",
            scopes=["authenticated"],
            type="view",
        ),
    ]

    """
  Centreon only supports the following host state (UP = 0, DOWN = 2, UNREA = 3)
  https://docs.centreon.com/docs/api/rest-api-v1/#realtime-information
  """

    STATUS_MAP = {
        2: AlertStatus.FIRING,
        3: AlertStatus.FIRING,
        0: AlertStatus.RESOLVED,
    }

    SEVERITY_MAP = {
        "CRITICAL": AlertSeverity.CRITICAL,
        "WARNING": AlertSeverity.WARNING,
        "UNKNOWN": AlertSeverity.INFO,
        "OK": AlertSeverity.LOW,
        "PENDING": AlertSeverity.INFO,
    }

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        self._auth_token: str | None = None
        super().__init__(context_manager, provider_id, config)

    def dispose(self):
        pass

    def validate_config(self):
        """
        Validates the configuration of the Centreon provider.
        """
        self.authentication_config = CentreonProviderAuthConfig(
            **self.config.authentication
        )

        self.__authenticate()

    def __get_url(self, path: str):
        """Build API V2 url.

        Historically ``host_url`` was expected without the ``/centreon`` suffix.
        Some installations provide the API under ``https://host/centreon``. This
        helper handles both configurations gracefully.
        """

        host = self.authentication_config.host_url.rstrip("/")
        if host.endswith("/centreon"):
            base = f"{host}/api/latest/"
        else:
            base = f"{host}/centreon/api/latest/"

        return base + path.lstrip("/")

    def __get_login_url(self) -> str:
        host = self.authentication_config.host_url.rstrip("/")
        if host.endswith("/centreon"):
            base = host
        else:
            base = f"{host}/centreon"
        return f"{base}/api/index.php?action=authenticate"

    def __authenticate(self) -> None:
        """Authenticate using the modern login endpoint and fallback to legacy."""

        # First try the modern ``/api/latest/login`` endpoint
        url = self.__get_url("login")
        payload = {
            "security": {
                "credentials": {
                    "login": self.authentication_config.username,
                    "password": self.authentication_config.password,
                }
            }
        }

        try:
            response = requests.post(url, json=payload)
            if response.ok:
                data = {}
                try:
                    data = response.json()
                except Exception:
                    pass
                token = (
                    data.get("security", {}).get("token")
                    or data.get("token")
                    or data.get("authToken")
                    or data.get("auth_token")
                    or data.get("security_token")
                )
                if not token:
                    token = response.text.strip().strip('"')
                if not token:
                    raise ProviderException("Missing auth token in Centreon response")
                self._auth_token = token
                return
        except Exception:
            # fall back to legacy authentication
            pass

        # Fallback to legacy ``/api/index.php?action=authenticate`` endpoint
        url = self.__get_login_url()
        payload = {
            "username": self.authentication_config.username,
            "password": self.authentication_config.password,
        }
        try:
            response = requests.post(url, json=payload)
            if not response.ok:
                raise ProviderException(
                    f"Failed to authenticate with Centreon: {response.status_code} {response.text}"
                )
            data = {}
            try:
                data = response.json()
            except Exception:
                pass
            token = (
                data.get("authToken")
                or data.get("auth_token")
                or data.get("security_token")
                or data.get("token")
            )
            if not token:
                token = response.text.strip().strip('"')
            if not token:
                raise ProviderException("Missing auth token in Centreon response")
            self._auth_token = token
        except Exception as e:
            raise ProviderException(f"Error authenticating with Centreon: {e}") from e

    def __get_headers(self):
        headers = {"Content-Type": "application/json"}
        if self._auth_token:
            headers["X-AUTH-TOKEN"] = self._auth_token
        return headers

    @staticmethod
    def _format_host_alert(
        host: dict, provider_instance: BaseProvider | None = None
    ) -> AlertDto:
        return AlertDto(
            id=host["id"],
            name=host["name"],
            address=host["address"],
            description=host["output"],
            status=CentreonProvider.STATUS_MAP.get(host["state"], AlertStatus.FIRING),
            severity=CentreonProvider.SEVERITY_MAP.get(
                host["output"].split()[0], AlertSeverity.INFO
            ),
            instance_name=host["instance_name"],
            acknowledged=host["acknowledged"],
            max_check_attempts=host["max_check_attempts"],
            lastReceived=datetime.datetime.fromtimestamp(
                host["last_check"]
            ).isoformat(),
            source=["centreon"],
        )

    @staticmethod
    def _format_service_alert(
        service: dict, provider_instance: BaseProvider | None = None
    ) -> AlertDto:
        return AlertDto(
            id=str(service.get("service_id") or service.get("id")),
            host_id=service.get("host_id"),
            name=service["name"],
            description=service["description"],
            status=CentreonProvider.STATUS_MAP.get(
                service["state"], AlertStatus.FIRING
            ),
            severity=CentreonProvider.SEVERITY_MAP.get(
                service["output"].split(":")[0], AlertSeverity.INFO
            ),
            acknowledged=service["acknowledged"],
            max_check_attempts=service["max_check_attempts"],
            lastReceived=datetime.datetime.fromtimestamp(
                service["last_check"]
            ).isoformat(),
            source=["centreon"],
        )

    @staticmethod
    def _format_resource_alert(
        resource: dict, provider_instance: BaseProvider | None = None
    ) -> AlertDto:
        status = resource.get("status", {})
        status_name = status.get("name", "").upper()
        status_code = status.get("code")

        return AlertDto(
            id=str(
                resource.get("service_id")
                or resource.get("host_id")
                or resource.get("id")
            ),
            host_id=resource.get("host_id"),
            service_id=resource.get("service_id"),
            name=resource.get("name"),
            description=resource.get("information"),
            status=(
                CentreonProvider.STATUS_MAP.get(status_code, AlertStatus.FIRING)
                if status_code is not None
                else (
                    AlertStatus.RESOLVED
                    if status_name in ("OK", "UP")
                    else AlertStatus.FIRING
                )
            ),
            severity=CentreonProvider.SEVERITY_MAP.get(status_name, AlertSeverity.INFO),
            acknowledged=resource.get("is_acknowledged"),
            lastReceived=resource.get("last_status_change")
            or datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=["centreon"],
        )

    def __get_paginated_data(self, path: str, params: dict | None = None) -> list[dict]:
        """Retrieve all pages for the given API path.

        Parameters
        ----------
        path: str
            API path to query (without the leading host).
        params: dict | None
            Additional query parameters to include in the request.
        """
        page = 1
        limit = 50
        results: list[dict] = []

        params = params or {}

        while True:
            query = params.copy()
            query.update({"page": page, "limit": limit})
            url = self.__get_url(path)
            response = requests.get(url, headers=self.__get_headers(), params=query)

            if not response.ok:
                self.logger.error(
                    "Failed to get %s from Centreon: %s", path, response.text
                )
                raise ProviderException(f"Failed to get {path} from Centreon")

            data = response.json()

            meta: dict | None = None

            # Some Centreon deployments wrap the results in a "result" or
            # "data" key as well as providing a "meta" key for pagination.
            if isinstance(data, dict):
                meta = data.get("meta")
                data = (
                    data.get("result")
                    or data.get("data")
                    or data.get(path.split("/")[-1])
                    or []
                )

            if not data:
                break

            results.extend(data)

            # When the API returns pagination information use it to decide
            # whether additional requests are required. Fallback to the
            # previous behaviour if no meta is supplied.
            if meta:
                page = meta.get("page", page)
                limit = meta.get("limit", limit)
                total = meta.get("total")
                if total is not None and page * limit >= total:
                    break
                page += 1
            else:
                if len(data) < limit:
                    break
                page += 1

        return results

    def validate_scopes(self) -> dict[str, bool | str]:
        """
        Validate the scopes of the provider.
        """
        try:
            response = requests.get(
                self.__get_url("monitoring/hosts?page=1&limit=1"),
                headers=self.__get_headers(),
            )
            if response.ok:
                scopes = {"authenticated": True}
            else:
                scopes = {
                    "authenticated": f"Error validating scopes: {response.status_code} {response.text}"
                }
        except Exception as e:
            scopes = {
                "authenticated": f"Error validating scopes: {e}",
            }

        return scopes

    def __get_host_status(self) -> list[AlertDto]:
        try:
            hosts = self.__get_paginated_data("monitoring/hosts")

            return [self._format_host_alert(host, self) for host in hosts]

        except Exception as e:
            self.logger.error("Error getting host status from Centreon: %s", e)
            raise ProviderException(
                f"Error getting host status from Centreon: {e}"
            ) from e

    def __get_service_status(self) -> list[AlertDto]:
        try:
            services = self.__get_paginated_data("monitoring/services")

            return [self._format_service_alert(service, self) for service in services]

        except Exception as e:
            self.logger.error("Error getting service status from Centreon: %s", e)
            raise ProviderException(
                f"Error getting service status from Centreon: {e}"
            ) from e

    def __get_resource_status(self) -> list[AlertDto]:
        """Retrieve alerts from the unified ``monitoring/resources`` endpoint."""

        params = {
            "status_types": '["hard"]',
            # Centreon expects status values in upper case
            # see https://docs.centreon.com/api/
            "status": '["WARNING","DOWN","UNREACHABLE","CRITICAL","UNKNOWN"]',
            "states": '["unhandled"]',
        }

        try:
            resources = self.__get_paginated_data("monitoring/resources", params=params)
            return [self._format_resource_alert(res, self) for res in resources]
        except Exception as e:
            self.logger.error("Error getting resource status from Centreon: %s", e)
            raise ProviderException(
                f"Error getting resource status from Centreon: {e}"
            ) from e

    def acknowledge_alert(
        self,
        host_id: str,
        service_id: str = None,
        comment: str | None = None,
    ) -> bool:
        """Acknowledge a host or service alert in Centreon."""

        try:
            payload = {
                "comment": comment or "Acknowledged via Keep",
                "is_notify_contacts": False,
                "is_persistent_comment": True,
                "is_sticky": True,
            }

            if service_id:
                path = (
                    f"monitoring/hosts/{host_id}/services/{service_id}/acknowledgements"
                )
            else:
                path = f"monitoring/hosts/{host_id}/acknowledgements"

            response = requests.post(
                self.__get_url(path),
                headers=self.__get_headers(),
                json=payload,
            )

            if not response.ok:
                self.logger.error(
                    "Failed to acknowledge alert in Centreon: %s", response.text
                )
                raise ProviderException("Failed to acknowledge alert in Centreon")

            self.logger.info(
                "Acknowledged alert in Centreon",
                extra={"host_id": host_id, "service_id": service_id},
            )

            return True
        except Exception as e:
            self.logger.error("Error acknowledging alert in Centreon: %s", e)
            raise ProviderException(
                f"Error acknowledging alert in Centreon: {e}"
            ) from e

    def __parse_timestamp(self, value: typing.Any) -> float:
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
            except ValueError:
                try:
                    return float(value)
                except ValueError:
                    pass
        return datetime.datetime.now(datetime.timezone.utc).timestamp()

    def get_alert_status(self, host_id: str, service_id: str | None = None) -> AlertDto:
        """Get the current status of a host or service."""
        try:
            if service_id:
                path = f"monitoring/hosts/{host_id}/services/{service_id}"
            else:
                path = f"monitoring/hosts/{host_id}"

            response = requests.get(self.__get_url(path), headers=self.__get_headers())

            if not response.ok:
                self.logger.error("Failed to get alert status from Centreon: %s", response.text)
                raise ProviderException("Failed to get alert status from Centreon")

            data = response.json()
            if isinstance(data, dict):
                data = data.get("result") or data.get("data") or data

            if service_id:
                if isinstance(data, list):
                    data = data[0] if data else {}
                if "last_check" in data:
                    data["last_check"] = self.__parse_timestamp(data["last_check"])
                return self._format_service_alert(data, self)
            else:
                if isinstance(data, list):
                    data = data[0] if data else {}
                if "last_check" in data:
                    data["last_check"] = self.__parse_timestamp(data["last_check"])
                return self._format_host_alert(data, self)
        except Exception as e:
            self.logger.error("Error getting alert status from Centreon: %s", e)
            raise ProviderException(f"Error getting alert status from Centreon: {e}") from e

    def _notify(
        self,
        action: typing.Literal["acknowledge_alert"] = "acknowledge_alert",
        host_id: str = "",
        service_id: str | None = None,
        comment: str | None = None,
        **kwargs: dict,
    ) -> bool:
        """Run Centreon actions.

        Currently supports acknowledging alerts via ``acknowledge_alert``.
        """

        if action == "acknowledge_alert":
            return self.acknowledge_alert(
                host_id=host_id, service_id=service_id, comment=comment
            )

        raise NotImplementedError(f"Action {action} is not implemented")

    def _get_alerts(self) -> list[AlertDto]:
        try:
            self.logger.info("Collecting alerts from Centreon resources")
            return self.__get_resource_status()
        except Exception as e:
            self.logger.error("Error getting resource status from Centreon: %s", e)
            return []


if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler()])
    context_manager = ContextManager(
        tenant_id="singletenant",
        workflow_id="test",
    )

    import os

    host_url = os.environ.get("CENTREON_HOST_URL")
    username = os.environ.get("CENTREON_USERNAME")
    password = os.environ.get("CENTREON_PASSWORD")

    if host_url is None:
        raise ProviderException("CENTREON_HOST_URL is not set")

    config = ProviderConfig(
        description="Centreon Provider",
        authentication={
            "host_url": host_url,
            "username": username,
            "password": password,
        },
    )

    provider = CentreonProvider(
        context_manager,
        provider_id="centreon",
        config=config,
    )

    provider._get_alerts()
