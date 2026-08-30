import json
from pathlib import Path

CONFIG = Path('config/marketing-stage4-clients.json')
REQUIRED_CLIENTS = {
    'codestra-marketing',
    'codestra-ai',
    'codestra-communication',
    'codestra-social',
    'codestra-n8n-marketing',
}
REQUIRED_SCOPES = {
    'marketing.read', 'marketing.write', 'marketing.approve', 'marketing.provider.read',
    'ai.generate', 'communication.send', 'communication.read',
    'social.read', 'social.write', 'social.publish',
}
FORBIDDEN_AUTOMATION = {
    'marketing.approve', 'marketing.provider.write', 'marketing.budget.raise',
}


def main() -> None:
    data = json.loads(CONFIG.read_text(encoding='utf-8'))
    clients = {c['clientId']: c for c in data['clients']}
    missing = sorted(REQUIRED_CLIENTS - set(clients))
    assert not missing, f'missing_clients:{missing}'
    for client_id, client in clients.items():
        assert client.get('serviceAccountsEnabled') is True, f'service_account_required:{client_id}'
        assert client.get('publicClient') is False, f'confidential_client_required:{client_id}'
        assert client.get('standardFlowEnabled') is False, f'user_flow_forbidden:{client_id}'
        assert 'secret' not in client, f'secret_must_not_be_committed:{client_id}'
    scopes = set(data.get('clientScopes', []))
    assert REQUIRED_SCOPES <= scopes, f'missing_scopes:{sorted(REQUIRED_SCOPES - scopes)}'
    forbidden = set(data.get('forbiddenAutomationScopes', []))
    assert FORBIDDEN_AUTOMATION <= forbidden, 'automation_denials_incomplete'
    text = CONFIG.read_text(encoding='utf-8').lower()
    assert 'clientsecret' not in text and '"secret"' not in text
    assert 'apply directly to production' not in text.lower().replace('do not apply directly to production', '')
    print('MARKETING_IDENTITY_STAGE5_CERTIFICATION=PASS')


if __name__ == '__main__':
    main()
