import unittest

from keep.api.models.alert import AlertSeverity, AlertStatus
from keep.providers.centreon_provider.centreon_provider import CentreonProvider


class TestCentreonProvider(unittest.TestCase):
    def test_format_host_alert(self):
        host = {
            "id": "1",
            "name": "db1",
            "address": "10.0.0.1",
            "output": "OK running",
            "state": 0,
            "instance_name": "inst1",
            "acknowledged": False,
            "max_check_attempts": 3,
            "last_check": 1700000000,
        }
        alert = CentreonProvider._format_host_alert(host)
        self.assertEqual(alert.status, AlertStatus.RESOLVED)
        self.assertEqual(alert.severity, AlertSeverity.LOW)

    def test_format_host_alert_down(self):
        host = {
            "id": "2",
            "name": "db2",
            "address": "10.0.0.2",
            "output": "DOWN",
            "state": 1,
            "instance_name": "inst2",
            "acknowledged": False,
            "max_check_attempts": 3,
            "last_check": 1700000000,
        }
        alert = CentreonProvider._format_host_alert(host)
        self.assertEqual(alert.status, AlertStatus.FIRING)

    def test_format_service_alert(self):
        service = {
            "service_id": "2",
            "host_id": "1",
            "name": "HTTP",
            "description": "http check",
            "state": 2,
            "output": "CRITICAL: down",
            "acknowledged": False,
            "max_check_attempts": 3,
            "last_check": 1700000000,
        }
        alert = CentreonProvider._format_service_alert(service)
        self.assertEqual(alert.status, AlertStatus.FIRING)
        self.assertEqual(alert.severity, AlertSeverity.CRITICAL)

    def test_format_service_alert_with_host_info(self):
        service = {
            "service_id": "2",
            "host_id": "1",
            "name": "HTTP",
            "description": "http check",
            "state": 2,
            "output": "CRITICAL: down",
            "acknowledged": False,
            "max_check_attempts": 3,
            "last_check": 1700000000,
        }

        class DummyProvider:
            def __init__(self):
                import logging

                self.logger = logging.getLogger("dummy")

            def _CentreonProvider__get_host_configuration(self, host_id):
                return {
                    "name": "srv1",
                    "alias": "server1",
                    "groups": [{"id": 1, "name": "grp1"}],
                }

        alert = CentreonProvider._format_service_alert(service, DummyProvider())

        self.assertEqual(alert.name, "srv1 - HTTP")
        self.assertEqual(alert.alias, "server1")
        self.assertEqual(alert.groups, [{"id": 1, "name": "grp1"}])

    def test_format_service_alert_unknown(self):
        service = {
            "service_id": "4",
            "host_id": "1",
            "name": "Disk",
            "description": "disk check",
            "state": 3,
            "output": "UNKNOWN: ?",
            "acknowledged": False,
            "max_check_attempts": 3,
            "last_check": 1700000000,
        }
        alert = CentreonProvider._format_service_alert(service)
        self.assertEqual(alert.status, AlertStatus.FIRING)

    def test_format_service_alert_with_id(self):
        service = {
            "id": "3",
            "host_id": "1",
            "name": "HTTPS",
            "description": "https check",
            "state": 1,
            "output": "WARNING: slow",
            "acknowledged": True,
            "max_check_attempts": 5,
            "last_check": 1700000001,
        }
        alert = CentreonProvider._format_service_alert(service)
        self.assertEqual(alert.id, "3")
        self.assertEqual(alert.status, AlertStatus.FIRING)

    def test_format_resource_alert_with_host_info(self):
        resource = {
            "host_id": "1",
            "service_id": "2",
            "name": "Ping",
            "information": "CRITICAL",
            "status": {"name": "CRITICAL", "code": 2},
            "is_acknowledged": False,
            "last_status_change": "2019-08-24T14:15:22Z",
        }

        class DummyProvider:
            def __init__(self):
                import logging

                self.logger = logging.getLogger("dummy")

            def _CentreonProvider__get_host_configuration(self, host_id):
                return {
                    "name": "srv1",
                    "alias": "server1",
                    "groups": [{"id": 1, "name": "grp1"}],
                }

        alert = CentreonProvider._format_resource_alert(resource, DummyProvider())

        self.assertEqual(alert.name, "srv1 - Ping")
        self.assertEqual(alert.alias, "server1")
        self.assertEqual(alert.groups, [{"id": 1, "name": "grp1"}])

    def test_get_paginated_data(self):
        from unittest.mock import patch

        from keep.contextmanager.contextmanager import ContextManager
        from keep.providers.models.provider_config import ProviderConfig

        context_manager = ContextManager(tenant_id="test")
        with patch(
            "keep.providers.centreon_provider.centreon_provider.requests.post"
        ) as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.json.return_value = {"auth_token": "tok"}

            provider = CentreonProvider(
                context_manager,
                provider_id="centreon",
                config=ProviderConfig(
                    description="centreon",
                    authentication={
                        "host_url": "http://localhost",
                        "username": "u",
                        "password": "p",
                    },
                ),
            )

        # Mock paginated responses: first page 50 items, second page 10 items
        class MockResp:
            def __init__(self, data):
                self._data = data
                self.ok = True
                self.text = str(data)

            def json(self):
                return self._data

        first_page = {
            "meta": {"page": 1, "limit": 50, "total": 60},
            "result": [
                {
                    "id": str(i),
                    "address": "",
                    "output": "",
                    "state": 0,
                    "instance_name": "i",
                    "acknowledged": False,
                    "max_check_attempts": 1,
                    "last_check": 0,
                }
                for i in range(50)
            ],
        }
        second_page = {
            "meta": {"page": 2, "limit": 50, "total": 60},
            "result": [
                {
                    "id": str(50 + i),
                    "address": "",
                    "output": "",
                    "state": 0,
                    "instance_name": "i",
                    "acknowledged": False,
                    "max_check_attempts": 1,
                    "last_check": 0,
                }
                for i in range(10)
            ],
        }

        with patch(
            "keep.providers.centreon_provider.centreon_provider.requests.get"
        ) as mock_get:
            mock_get.side_effect = [MockResp(first_page), MockResp(second_page)]
            data = provider._CentreonProvider__get_paginated_data("monitoring/hosts")
            self.assertEqual(len(data), 60)

    def test_get_resource_status_params(self):
        """Ensure _get_alerts queries the correct resource endpoint."""
        from unittest.mock import patch

        from keep.contextmanager.contextmanager import ContextManager
        from keep.providers.models.provider_config import ProviderConfig

        context_manager = ContextManager(tenant_id="test")
        with patch(
            "keep.providers.centreon_provider.centreon_provider.requests.post"
        ) as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.json.return_value = {"auth_token": "tok"}

            provider = CentreonProvider(
                context_manager,
                provider_id="centreon",
                config=ProviderConfig(
                    description="centreon",
                    authentication={
                        "host_url": "http://localhost",
                        "username": "u",
                        "password": "p",
                    },
                ),
            )

        class MockResp:
            def __init__(self):
                self.ok = True
                self.text = "{}"

            def json(self):
                return {"result": [], "meta": {"page": 1, "limit": 50, "total": 0}}

        with patch(
            "keep.providers.centreon_provider.centreon_provider.requests.get"
        ) as mock_get:
            mock_get.return_value = MockResp()
            provider._get_alerts()
            called_url = mock_get.call_args[0][0]
            params = mock_get.call_args[1]["params"]

            expected_url = "http://localhost/centreon/api/latest/monitoring/resources"
            assert called_url == expected_url
            assert params["states"] == '["unhandled_problems"]'
            assert (
                params["status"]
                == '["WARNING","DOWN","UNREACHABLE","CRITICAL","UNKNOWN"]'
            )

    def test_acknowledge_alert_service_url(self):
        from unittest.mock import patch

        from keep.contextmanager.contextmanager import ContextManager
        from keep.providers.models.provider_config import ProviderConfig

        context_manager = ContextManager(tenant_id="test")
        with patch(
            "keep.providers.centreon_provider.centreon_provider.requests.post"
        ) as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.json.return_value = {"auth_token": "tok"}

            provider = CentreonProvider(
                context_manager,
                provider_id="centreon",
                config=ProviderConfig(
                    description="centreon",
                    authentication={
                        "host_url": "http://localhost",
                        "username": "u",
                        "password": "p",
                    },
                ),
            )

        with patch(
            "keep.providers.centreon_provider.centreon_provider.requests.post"
        ) as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.text = ""

            provider.acknowledge_alert(host_id="1", service_id="2", comment="c")
            called_url = mock_post.call_args[0][0]

            expected_url = (
                "http://localhost/centreon/api/latest/"
                "monitoring/hosts/1/services/2/acknowledgements"
            )
            self.assertEqual(called_url, expected_url)

    def test_acknowledge_alert_payload(self):
        from unittest.mock import patch

        from keep.contextmanager.contextmanager import ContextManager
        from keep.providers.models.provider_config import ProviderConfig

        context_manager = ContextManager(tenant_id="test")
        with patch(
            "keep.providers.centreon_provider.centreon_provider.requests.post"
        ) as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.json.return_value = {"auth_token": "tok"}

            provider = CentreonProvider(
                context_manager,
                provider_id="centreon",
                config=ProviderConfig(
                    description="centreon",
                    authentication={
                        "host_url": "http://localhost",
                        "username": "u",
                        "password": "p",
                    },
                ),
            )

        with patch(
            "keep.providers.centreon_provider.centreon_provider.requests.post"
        ) as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.text = ""

            provider.acknowledge_alert(host_id="1", service_id="2")
            called_payload = mock_post.call_args.kwargs["json"]

            expected_payload = {
                "comment": "Acknowledged via Keep",
                "is_notify_contacts": False,
                "is_persistent_comment": True,
                "is_sticky": True,
            }

            self.assertEqual(called_payload, expected_payload)

    def test_authenticate_with_username_password(self):
        from unittest.mock import patch

        from keep.contextmanager.contextmanager import ContextManager
        from keep.providers.models.provider_config import ProviderConfig

        context_manager = ContextManager(tenant_id="test")

        with patch(
            "keep.providers.centreon_provider.centreon_provider.requests.post"
        ) as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.json.return_value = {"auth_token": "tok"}

            provider = CentreonProvider(
                context_manager,
                provider_id="centreon",
                config=ProviderConfig(
                    description="centreon",
                    authentication={
                        "host_url": "http://localhost",
                        "username": "u",
                        "password": "p",
                    },
                ),
            )

            headers = provider._CentreonProvider__get_headers()
            self.assertEqual(headers.get("X-AUTH-TOKEN"), "tok")

    def test_get_alert_status_service(self):
        from unittest.mock import patch

        from keep.contextmanager.contextmanager import ContextManager
        from keep.providers.models.provider_config import ProviderConfig

        context_manager = ContextManager(tenant_id="test")

        with patch(
            "keep.providers.centreon_provider.centreon_provider.requests.post"
        ) as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.json.return_value = {"auth_token": "tok"}

            provider = CentreonProvider(
                context_manager,
                provider_id="centreon",
                config=ProviderConfig(
                    description="centreon",
                    authentication={
                        "host_url": "http://localhost",
                        "username": "u",
                        "password": "p",
                    },
                ),
            )

        service_resp = {
            "id": 5,
            "name": "Ping",
            "description": "Ping",
            "state": 0,
            "acknowledged": False,
            "max_check_attempts": 3,
            "last_check": "2019-08-24T14:15:22Z",
            "output": "OK",
        }

        with patch(
            "keep.providers.centreon_provider.centreon_provider.requests.get"
        ) as mock_get:
            mock_get.return_value.ok = True
            mock_get.return_value.json.return_value = service_resp

            alert = provider.get_alert_status(host_id="12", service_id="5")
            called_url = mock_get.call_args[0][0]

            expected_url = (
                "http://localhost/centreon/api/latest/monitoring/hosts/12/services/5"
            )
            self.assertEqual(called_url, expected_url)
            self.assertEqual(alert.status, AlertStatus.RESOLVED)
            self.assertEqual(alert.id, "5")

    def test_get_alert_status_host(self):
        from unittest.mock import patch

        from keep.contextmanager.contextmanager import ContextManager
        from keep.providers.models.provider_config import ProviderConfig

        context_manager = ContextManager(tenant_id="test")

        with patch(
            "keep.providers.centreon_provider.centreon_provider.requests.post"
        ) as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.json.return_value = {"auth_token": "tok"}

            provider = CentreonProvider(
                context_manager,
                provider_id="centreon",
                config=ProviderConfig(
                    description="centreon",
                    authentication={
                        "host_url": "http://localhost",
                        "username": "u",
                        "password": "p",
                    },
                ),
            )

        host_resp = {
            "id": 12,
            "name": "Central",
            "address": "127.0.0.1",
            "output": "OK",
            "state": 0,
            "instance_name": "inst1",
            "acknowledged": False,
            "max_check_attempts": 3,
            "last_check": "2019-08-24T14:15:22Z",
        }

        with patch(
            "keep.providers.centreon_provider.centreon_provider.requests.get"
        ) as mock_get:
            mock_get.return_value.ok = True
            mock_get.return_value.json.return_value = host_resp

            alert = provider.get_alert_status(host_id="12")
            called_url = mock_get.call_args[0][0]

            expected_url = "http://localhost/centreon/api/latest/monitoring/hosts/12"
            self.assertEqual(called_url, expected_url)
            self.assertEqual(alert.status, AlertStatus.RESOLVED)
            self.assertEqual(alert.id, 12)


if __name__ == "__main__":
    unittest.main()
