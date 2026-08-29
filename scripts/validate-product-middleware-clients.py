#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
CONTRACT=ROOT/'config/contracts/product-middleware-clients.json'
CLIENT_DIR=ROOT/'config/clients'
ALLOWLIST_DIR=ROOT/'config/export-allowlists'
MANAGED=ROOT/'config/policy/managed-clients.json'
CREATABLE=ROOT/'config/policy/creatable-clients.json'
EXPECTED={
'moneybee-backend':(['moneybee.middleware.command.write','moneybee.middleware.status.read'],['crm.'],['odoo-19']),
'breero-backend':(['breero.middleware.command.write','breero.middleware.status.read'],['crm.'],['odoo-19']),
'larim-a-backend':(['larim-a.middleware.command.write','larim-a.middleware.status.read'],['crm.'],['odoo-19']),
'transportation-backend':(['transportation.middleware.command.write','transportation.middleware.status.read'],['crm.'],['odoo-19']),
'beyvra-backend':(['beyvra.middleware.command.write','beyvra.middleware.status.read'],['crm.'],['odoo-19']),
'social-codestra':(['social.middleware.command.write','social.middleware.status.read'],['social.'],['postly-social'])}
TOP=['clientId','name','description','enabled','protocol','publicClient','bearerOnly','consentRequired','standardFlowEnabled','implicitFlowEnabled','directAccessGrantsEnabled','serviceAccountsEnabled','authorizationServicesEnabled','frontchannelLogout','fullScopeAllowed','redirectUris','webOrigins','defaultClientScopes','optionalClientScopes','attributes','protocolMappers']
ATTR=['access.token.lifespan','oauth2.device.authorization.grant.enabled','oidc.ciba.grant.enabled']
def load(p):
 v=json.loads(p.read_text(encoding='utf-8')); assert isinstance(v,dict),p; return v
def mapper(c,n):
 m=[x for x in c['protocolMappers'] if x.get('name')==n]; assert len(m)==1,(c['clientId'],n); return m[0]
def main():
 c=load(CONTRACT)
 assert c['schemaVersion']==1 and c['issuer']=='https://auth.codestra.co/realms/codestra' and c['audience']=='middleware-api'
 assert c['grantType']=='client_credentials' and c['maximumAccessTokenLifetimeSeconds']==300 and c['refreshTokensAllowed'] is False
 assert c['tokenExchange'] is False and c['forwardOriginalBearer'] is True and c['directProviderAccess'] is False
 assert c['tenantClaim']=={'claim':'tenant_id','source':'service-account-user-attribute','attribute':'tenant_id','wildcardAllowed':False}
 assert [x['clientId'] for x in c['clients']]==list(EXPECTED)
 managed=load(MANAGED)['clients']; creatable=load(CREATABLE)['clients']
 for item in c['clients']:
  cid=item['clientId']; scopes,prefixes,targets=EXPECTED[cid]
  assert item['scopes']==scopes and item['allowedCommandPrefixes']==prefixes and item['allowedTargets']==targets
  assert cid in managed and cid in creatable
  d=load(CLIENT_DIR/f'{cid}.json')
  assert d['clientId']==cid and d['enabled'] is True and d['protocol']=='openid-connect'
  assert d['publicClient'] is False and d['bearerOnly'] is False and d['standardFlowEnabled'] is False and d['implicitFlowEnabled'] is False
  assert d['directAccessGrantsEnabled'] is False and d['serviceAccountsEnabled'] is True and d['authorizationServicesEnabled'] is False and d['fullScopeAllowed'] is False
  assert d['redirectUris']==[] and d['webOrigins']==[] and d['defaultClientScopes']==[] and d['optionalClientScopes']==[]
  assert d['attributes']=={'access.token.lifespan':'300','oauth2.device.authorization.grant.enabled':'false','oidc.ciba.grant.enabled':'false'}
  a=mapper(d,'audience-middleware-api'); assert a['protocolMapper']=='oidc-audience-mapper' and a['config']=={'included.custom.audience':'middleware-api','id.token.claim':'false','access.token.claim':'true'}
  s=mapper(d,'reviewed-product-middleware-scopes'); assert s['protocolMapper']=='oidc-hardcoded-claim-mapper' and s['config']['claim.name']=='scope' and s['config']['claim.value']==' '.join(scopes)
  t=mapper(d,'tenant-id-from-service-account'); assert t['protocolMapper']=='oidc-usermodel-attribute-mapper' and t['config']=={'user.attribute':'tenant_id','claim.name':'tenant_id','jsonType.label':'String','id.token.claim':'false','access.token.claim':'true','userinfo.token.claim':'false','multivalued':'false'}
  al=load(ALLOWLIST_DIR/f'{cid}.json'); assert al=={'clientId':cid,'topLevelFields':TOP,'attributeFields':ATTR}
 for cid in ('breero-backend','larim-a-backend','transportation-backend'):
  assert 'telephony.' not in EXPECTED[cid][1]
 assert 'crm.' not in EXPECTED['social-codestra'][1]
 print('PRODUCT_MIDDLEWARE_CLIENTS=PASS')
if __name__=='__main__': main()
