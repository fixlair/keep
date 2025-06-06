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


if __name__ == "__main__":
    unittest.main()
