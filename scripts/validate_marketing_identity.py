from pathlib import Path

REQUIRED_CLIENTS = ['marketing', 'ai', 'communication', 'social', 'middleware', 'n8n', 'odoo']
FORBIDDEN_AUTOMATION = ['marketing:approve', 'marketing:provider-write']


def main() -> None:
    files = list(Path('.').rglob('*.json')) + list(Path('.').rglob('*.yml')) + list(Path('.').rglob('*.yaml'))
    text = '\n'.join(p.read_text(encoding='utf-8', errors='ignore').lower() for p in files)
    for client in REQUIRED_CLIENTS:
        assert client in text, f'missing_client:{client}'
    for scope in FORBIDDEN_AUTOMATION:
        assert f'n8n:{scope}' not in text and f'automation:{scope}' not in text, f'automation_scope_forbidden:{scope}'
    print('marketing identity certification passed')


if __name__ == '__main__':
    main()
