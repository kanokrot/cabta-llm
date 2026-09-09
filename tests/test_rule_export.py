import io
import zipfile

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.analysis_manager import AnalysisManager
from src.web.routes import reports


SIGMA_RULE = """title: CABTA export test
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: cmd.exe
  condition: selection
"""

YARA_RULE = """rule CABTA_Export_Test {
    strings:
        $marker = "cabta-export-test"
    condition:
        $marker
}
"""

SURICATA_RULE = (
    'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 '
    '(msg:"CABTA export test"; sid:1000001; rev:1;)'
)


@pytest.fixture
def report_client(tmp_path):
    reports._rule_export_states.clear()
    app = FastAPI()
    app.state.analysis_manager = AnalysisManager(
        db_path=str(tmp_path / 'analysis_jobs.db')
    )
    app.include_router(reports.router, prefix='/api/reports')
    job_id = app.state.analysis_manager.create_job('ioc', {'value': 'test'})
    app.state.analysis_manager.complete_job(
        job_id,
        {
            'detection_rules': {
                'kql': 'DeviceProcessEvents\n| take 10',
                'sigma': SIGMA_RULE,
                'yara': YARA_RULE,
                'suricata': SURICATA_RULE,
            }
        },
    )
    with TestClient(app) as client:
        yield client, app.state.analysis_manager, job_id
    reports._rule_export_states.clear()


def test_rule_starts_pending_and_download_requires_approval(report_client):
    client, _, job_id = report_client

    status = client.get(f'/api/reports/{job_id}/rules/kql/status')
    denied = client.get(f'/api/reports/{job_id}/rules/kql/download')

    assert status.status_code == 200
    assert status.json()['status'] == 'pending_export'
    assert denied.status_code == 403
    assert denied.json()['detail'] == (
        'KQL rule export requires explicit human approval'
    )


def test_approval_validates_and_individual_download_uses_expected_extension(
    report_client,
):
    client, _, job_id = report_client

    approval = client.post(
        f'/api/reports/{job_id}/rules/yara/approve',
        json={'approved_by': 'analyst-01'},
    )
    download = client.get(f'/api/reports/{job_id}/rules/yara/download')

    assert approval.status_code == 200
    assert approval.json()['status'] == 'approved'
    assert approval.json()['approved_by'] == 'analyst-01'
    assert approval.json()['approved_at']
    assert approval.json()['validation']['valid'] is True
    assert download.status_code == 200
    assert download.content.decode('utf-8').rstrip() == YARA_RULE.rstrip()
    assert f'analysis-{job_id}-yara.yar' in download.headers['content-disposition']


def test_invalid_rule_cannot_be_approved_or_exported(report_client):
    client, manager, job_id = report_client
    manager.complete_job(
        job_id,
        {'detection_rules': {'kql': 'DeviceEvents | where Name == "broken'}},
    )

    approval = client.post(
        f'/api/reports/{job_id}/rules/kql/approve',
        json={'approved_by': 'analyst-02'},
    )
    download = client.get(f'/api/reports/{job_id}/rules/kql/download')

    assert approval.status_code == 422
    assert approval.json()['detail']['message'] == (
        'Rule validation failed; export was not approved'
    )
    assert approval.json()['detail']['validation']['valid'] is False
    assert download.status_code == 403


def test_zip_requires_approval_for_every_selected_rule_and_contains_files(
    report_client,
):
    client, _, job_id = report_client
    client.post(
        f'/api/reports/{job_id}/rules/sigma/approve',
        json={'approved_by': 'reviewer'},
    )

    denied = client.get(
        f'/api/reports/{job_id}/rules/export/zip',
        params={'rule_types': 'sigma,yara'},
    )
    assert denied.status_code == 403
    assert denied.json()['detail'] == (
        'YARA rule export requires explicit human approval'
    )

    client.post(
        f'/api/reports/{job_id}/rules/yara/approve',
        json={'approved_by': 'reviewer'},
    )
    exported = client.get(
        f'/api/reports/{job_id}/rules/export/zip',
        params={'rule_types': 'sigma,yara'},
    )

    assert exported.status_code == 200
    assert exported.headers['content-type'] == 'application/zip'
    with zipfile.ZipFile(io.BytesIO(exported.content)) as archive:
        assert archive.namelist() == ['sigma.yml', 'yara.yar']
        assert archive.read('sigma.yml').decode('utf-8').rstrip() == SIGMA_RULE.rstrip()
        assert archive.read('yara.yar').decode('utf-8').rstrip() == YARA_RULE.rstrip()


def test_mark_deployed_is_record_only_and_requires_prior_approval(report_client):
    client, _, job_id = report_client

    denied = client.post(
        f'/api/reports/{job_id}/rules/suricata/mark-deployed',
        json={'deployed_by': 'operator-01'},
    )
    assert denied.status_code == 403

    client.post(
        f'/api/reports/{job_id}/rules/suricata/approve',
        json={'approved_by': 'analyst-03'},
    )
    deployed = client.post(
        f'/api/reports/{job_id}/rules/suricata/mark-deployed',
        json={'deployed_by': 'operator-01'},
    )

    assert deployed.status_code == 200
    assert deployed.json()['status'] == 'deployed'
    assert deployed.json()['deployed_by'] == 'operator-01'
    assert deployed.json()['deployed_at']
    assert deployed.json()['approved_by'] == 'analyst-03'


def test_changed_rule_content_returns_to_pending_export(report_client):
    client, manager, job_id = report_client
    client.post(
        f'/api/reports/{job_id}/rules/kql/approve',
        json={'approved_by': 'analyst-04'},
    )
    manager.complete_job(
        job_id,
        {'detection_rules': {'kql': 'DeviceNetworkEvents\n| take 20'}},
    )

    denied = client.get(f'/api/reports/{job_id}/rules/kql/download')
    status = client.get(f'/api/reports/{job_id}/rules/kql/status')

    assert denied.status_code == 403
    assert status.json()['status'] == 'pending_export'
    assert status.json()['approved_by'] is None
