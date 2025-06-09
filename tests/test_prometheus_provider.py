import uuid

from keep.providers.prometheus_provider.prometheus_provider import \
    PrometheusProvider


def test_format_alert_generates_uuid_for_id():
    event = {
        "alerts": [
            {
                "labels": {"alertname": "TestAlert", "severity": "critical"},
                "state": "firing",
                "annotations": {"summary": "summary"},
            }
        ]
    }
    alerts = PrometheusProvider._format_alert(event)
    assert len(alerts) == 1
    alert = alerts[0]
    # ensure id is a valid UUID and name preserved
    uuid.UUID(alert.id)
    assert alert.name == "TestAlert"
