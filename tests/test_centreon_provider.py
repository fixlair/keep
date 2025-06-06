import datetime
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

    def test_get_paginated_data(self):
        from unittest.mock import patch
        from keep.contextmanager.contextmanager import ContextManager
        from keep.providers.models.provider_config import ProviderConfig

        context_manager = ContextManager(tenant_id="test")
        provider = CentreonProvider(
            context_manager,
            provider_id="centreon",
            config=ProviderConfig(
                description="centreon",
                authentication={"host_url": "http://localhost", "api_token": "t"},
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

        first_page = [
            {"id": str(i), "address": "", "output": "", "state": 0, "instance_name": "i", "acknowledged": False, "max_check_attempts": 1, "last_check": 0}
            for i in range(50)
        ]
        second_page = [
            {"id": str(50 + i), "address": "", "output": "", "state": 0, "instance_name": "i", "acknowledged": False, "max_check_attempts": 1, "last_check": 0}
            for i in range(10)
        ]

        with patch("keep.providers.centreon_provider.centreon_provider.requests.get") as mock_get:
            mock_get.side_effect = [MockResp(first_page), MockResp(second_page)]
            data = provider._CentreonProvider__get_paginated_data("monitoring/hosts")
            self.assertEqual(len(data), 60)

    def test_acknowledge_alert_service_url(self):
        from unittest.mock import patch
        from keep.contextmanager.contextmanager import ContextManager
        from keep.providers.models.provider_config import ProviderConfig

        context_manager = ContextManager(tenant_id="test")
        provider = CentreonProvider(
            context_manager,
            provider_id="centreon",
            config=ProviderConfig(
                description="centreon",
                authentication={"host_url": "http://localhost", "api_token": "t"},
            ),
        )

        with patch("keep.providers.centreon_provider.centreon_provider.requests.post") as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.text = ""

            provider.acknowledge_alert(host_id="1", service_id="2", comment="c")
            called_url = mock_post.call_args[0][0]

            expected_url = (
                "http://localhost/centreon/api/latest/"
                "monitoring/hosts/1/services/2/acknowledgements"
            )
            self.assertEqual(called_url, expected_url)


if __name__ == "__main__":
    unittest.main()

