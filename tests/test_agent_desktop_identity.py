import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def load(p): return json.loads((ROOT/p).read_text())
def test_security():
 c=load('config/clients/codestra-agent-desktop.json'); assert c['publicClient'] and c['standardFlowEnabled']; assert not c['directAccessGrantsEnabled']; assert not c['implicitFlowEnabled']; assert c['attributes']['pkce.code.challenge.method']=='S256'; assert c['attributes']['access.token.lifespan']=='300'
def test_claims():
 m={x['name']:x for x in load('config/clients/codestra-agent-desktop.json')['protocolMappers']}; assert m['audience-codestra-agent-desktop']['config']['included.custom.audience']=='codestra-agent-desktop'; assert m['tenant-ids-from-user-attribute']['config']['claim.name']=='tenant_ids'
def test_roles():
 c=load('config/contracts/agent-desktop-realtime-client.json'); r=load('config/contracts/agent-desktop-client-roles.json'); assert c['requiredClientRoles']['codestra-agent-desktop']==[r['roles'][0]['name']]; assert 'telephony.webphone.use' in c['requiredRealmRoles']
def test_registration():
 for p in ('config/policy/managed-clients.json','config/policy/creatable-clients.json'): assert 'codestra-agent-desktop' in load(p)['clients']
