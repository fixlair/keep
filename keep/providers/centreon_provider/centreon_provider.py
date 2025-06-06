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

    api_token: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Centreon API Token",
            "sensitive": True,
        },
        default=None,
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
        )
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

    def __get_url(self, params: str):
        url = self.authentication_config.host_url + "/centreon/api/index.php?" + params
        return url

    def __get_headers(self):
        return {
            "Content-Type": "application/json",
            "centreon-auth-token": self.authentication_config.api_token,
        }

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
            id=service["service_id"],
            host_id=service["host_id"],
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

    def __get_paginated_data(self, object_name: str) -> list[dict]:
        """Retrieve all pages for the given object."""
        page = 1
        limit = 50
        results = []

        while True:
            params = f"object={object_name}&action=list&page={page}&limit={limit}"
            url = self.__get_url(params)
            response = requests.get(url, headers=self.__get_headers())

            if not response.ok:
                self.logger.error(
                    "Failed to get %s from Centreon: %s", object_name, response.text
                )
                raise ProviderException(f"Failed to get {object_name} from Centreon")

            data = response.json()

            # Some Centreon deployments wrap the results in a "result" or
            # "data" key. Handle these cases transparently so pagination works
            # regardless of the exact API version.
            if isinstance(data, dict):
                data = data.get("result") or data.get("data") or data.get(object_name) or []

            if not data:
                break

            results.extend(data)

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
                self.__get_url("object=centreon_realtime_hosts&action=list"),
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
            hosts = self.__get_paginated_data("centreon_realtime_hosts")

            return [self._format_host_alert(host, self) for host in hosts]

        except Exception as e:
            self.logger.error("Error getting host status from Centreon: %s", e)
            raise ProviderException(
                f"Error getting host status from Centreon: {e}"
            ) from e

    def __get_service_status(self) -> list[AlertDto]:
        try:
            services = self.__get_paginated_data("centreon_realtime_services")

            return [self._format_service_alert(service, self) for service in services]

        except Exception as e:
            self.logger.error("Error getting service status from Centreon: %s", e)
            raise ProviderException(
                f"Error getting service status from Centreon: {e}"
            ) from e

    def acknowledge_alert(
        self, host_id: str, service_id: str | None = None, comment: str | None = None
    ) -> bool:
        """Acknowledge a host or service alert in Centreon."""

        try:
            if service_id:
                params = "object=centreon_realtime_services&action=acknowledge"
                payload = {
                    "host_id": host_id,
                    "service_id": service_id,
                    "comment": comment,
                }
            else:
                params = "object=centreon_realtime_hosts&action=acknowledge"
                payload = {"host_id": host_id, "comment": comment}

            response = requests.post(
                self.__get_url(params),
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
        alerts = []
        try:
            self.logger.info("Collecting alerts (host status) from Centreon")
            host_status_alerts = self.__get_host_status()
            alerts.extend(host_status_alerts)
        except Exception as e:
            self.logger.error("Error getting host status from Centreon: %s", e)

        try:
            self.logger.info("Collecting alerts (service status) from Centreon")
            service_status_alerts = self.__get_service_status()
            alerts.extend(service_status_alerts)
        except Exception as e:
            self.logger.error("Error getting service status from Centreon: %s", e)

        return alerts


if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler()])
    context_manager = ContextManager(
        tenant_id="singletenant",
        workflow_id="test",
    )

    import os

    host_url = os.environ.get("CENTREON_HOST_URL")
    api_token = os.environ.get("CENTREON_API_TOKEN")

    if host_url is None:
        raise ProviderException("CENTREON_HOST_URL is not set")

    config = ProviderConfig(
        description="Centreon Provider",
        authentication={
            "host_url": host_url,
            "api_token": api_token,
        },
    )

    provider = CentreonProvider(
        context_manager,
        provider_id="centreon",
        config=config,
    )

    provider._get_alerts()
