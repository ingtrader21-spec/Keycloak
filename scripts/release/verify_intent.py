#!/usr/bin/env python3
"""Fail-closed repository-reviewed publication intent; never deployment authority."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def api(path):
    return json.loads(command('gh', 'api', path))


def pages(path):
    result = []
    for page in range(1, 101):
        rows = api(path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')
        require(isinstance(rows, list), 'Unexpected paginated response')
        result.extend(rows)
        if len(rows) < 100:
            return result
    raise ValueError('Pagination limit exceeded')


def validate_plan(plan, repo, requested_sha, expected_hash):
    encoded = json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()
    require(hashlib.sha256(encoded).hexdigest() == expected_hash, 'Plan hash mismatch')
    require(plan.get('schema') == 'reviewed-image-publication/v1', 'Unknown intent schema')
    require(plan.get('repository') == repo, 'Repository mismatch')
    require(plan.get('source_sha') == requested_sha, 'Source mismatch')
    require(bool(re.fullmatch('[0-9a-f]{40}', requested_sha)), 'Invalid source SHA')
    require(bool(re.fullmatch('[0-9a-f]{40}', plan.get('source_tree', ''))), 'Invalid tree SHA')
    require(plan.get('publish_image') is True, 'Publication not authorized')
    require(plan.get('deploy_production') is False, 'Deployment forbidden')
    require(plan.get('external_effects') is False, 'External effects forbidden')
    require(plan.get('sbom_required') is True and plan.get('provenance_required') is True, 'Attestations required')
    expected_image = {'appolon1908-hue/Keycloak': 'ghcr.io/appolon1908-hue/codestra-keycloak',
                      'appolon1908-hue/codestra-server-c': 'ghcr.io/appolon1908-hue/codestra-server-c'}
    require(repo in expected_image, 'Unrecognized repository')
    require(plan.get('image_repository') == expected_image.get(repo), 'Registry mismatch')


def approved_reviewers(pr, reviews, last_pusher):
    latest = {}
    for review in reviews:
        if review['state'] in ('APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'):
            latest[review['user']['login']] = review
    require(not any(r['state'] == 'CHANGES_REQUESTED' for r in latest.values()), 'Changes requested')
    return {login for login, review in latest.items()
            if review['state'] == 'APPROVED' and review['commit_id'] == pr['head']['sha']
            and login not in (pr['user']['login'], last_pusher)
            and review['user'].get('type') != 'Bot'}


def reviewed_commit(repo, sha, required_checks):
    for summary in pages(f'repos/{repo}/commits/{sha}/pulls'):
        pr = api(f'repos/{repo}/pulls/{summary["number"]}')
        if not pr['merged'] or pr['base']['ref'] != 'main':
            continue
        if sha not in (pr['merge_commit_sha'], pr['head']['sha']):
            continue
        commit = api(f'repos/{repo}/commits/{pr["head"]["sha"]}')
        pusher = (commit.get('committer') or {}).get('login')
        # Git commit email need not map to a GitHub user. GitHub's enforced
        # last-push approval rule governs the authenticated pusher independently.
        pusher = pusher or pr['user']['login']
        reviewers = approved_reviewers(pr, pages(f'repos/{repo}/pulls/{pr["number"]}/reviews'), pusher)
        require(reviewers, 'Independent exact-head approval missing')
        checks = api(f'repos/{repo}/commits/{pr["head"]["sha"]}/check-runs?per_page=100')
        require(checks['total_count'] <= 100, 'Check pagination requires review')
        latest = {}
        for check in sorted(checks['check_runs'], key=lambda x: x['id']):
            latest[check['name']] = check
        require(required_checks <= set(latest), 'Required CI absent')
        require(all(x['status'] == 'completed' and x['conclusion'] == 'success' for x in latest.values()), 'CI not fully green')
        owner, name = repo.split('/')
        query = 'query($o:String!,$n:String!,$p:Int!){repository(owner:$o,name:$n){pullRequest(number:$p){reviewThreads(first:100){pageInfo{hasNextPage} nodes{isResolved}}}}}'
        data = json.loads(command('gh', 'api', 'graphql', '-f', 'query=' + query, '-f', 'o=' + owner,
                                  '-f', 'n=' + name, '-F', 'p=' + str(pr['number'])))
        threads = data['data']['repository']['pullRequest']['reviewThreads']
        require(not threads['pageInfo']['hasNextPage'] and all(x['isResolved'] for x in threads['nodes']),
                'Unresolved or unenumerated review threads')
        return pr['number']
    raise ValueError('Merged reviewed PR missing for commit')


def protected_policy(repo):
    owner, name = repo.split('/')
    query = 'query($o:String!,$n:String!){repository(owner:$o,name:$n){ref(qualifiedName:"refs/heads/main"){branchProtectionRule{requiresApprovingReviews requiredApprovingReviewCount requireLastPushApproval dismissesStaleReviews isAdminEnforced allowsForcePushes}}}}'
    data = json.loads(command('gh', 'api', 'graphql', '-f', 'query=' + query, '-f', 'o=' + owner, '-f', 'n=' + name))
    rule = data['data']['repository']['ref']['branchProtectionRule']
    require(rule and rule['requiresApprovingReviews'] and rule['requiredApprovingReviewCount'] >= 1,
            'Review protection missing')
    require(rule['requireLastPushApproval'] and rule['dismissesStaleReviews'] and rule['isAdminEnforced']
            and not rule['allowsForcePushes'], 'Independent non-bypassable protection missing')


def main():
    repo = os.environ['GITHUB_REPOSITORY']
    require(os.environ['GITHUB_REF'] == 'refs/heads/main', 'Dispatch only from main')
    protected_policy(repo)
    branch = api(f'repos/{repo}/branches/main')
    require(branch['protected'] and branch['commit']['sha'] == os.environ['GITHUB_SHA'], 'Protected main drift')
    require(command('git', 'rev-parse', 'HEAD') == os.environ['GITHUB_SHA'], 'Authority checkout drift')
    path = Path(os.environ['RELEASE_INTENT_PATH'])
    require(re.fullmatch(r'release/intents/[A-Za-z0-9_-]+\.json', str(path)) is not None, 'Invalid intent path')
    require(path.is_file() and not path.is_symlink(), 'Intent missing or unsafe')
    plan = json.loads(path.read_text())
    validate_plan(plan, repo, os.environ['REQUESTED_SOURCE_SHA'], os.environ['RELEASE_PLAN_SHA256'])
    require(command('git', 'rev-parse', plan['source_sha'] + '^{tree}') == plan['source_tree'], 'Source tree drift')
    subprocess.run(['git', 'merge-base', '--is-ancestor', plan['source_sha'], 'HEAD'], check=True)
    required = {'validate-source', 'validate-merge-result'} if repo.endswith('/Keycloak') else {'backend', 'container'}
    required |= set(branch.get('protection', {}).get('required_status_checks', {}).get('contexts', []))
    source_pr = reviewed_commit(repo, plan['source_sha'], required)
    intent_commit = command('git', 'log', '-1', '--format=%H', '--', str(path))
    intent_pr = reviewed_commit(repo, intent_commit, required)
    require(source_pr != intent_pr, 'Release intent must be separately reviewed after source')
    evidence = {'source_sha': plan['source_sha'], 'source_tree': plan['source_tree'], 'source_pr': source_pr,
                'intent_pr': intent_pr, 'plan_sha256': os.environ['RELEASE_PLAN_SHA256'],
                'authority_sha': os.environ['GITHUB_SHA'], 'deployment_authorized': False}
    Path(os.environ['RUNNER_TEMP'], 'reviewed-publication.json').write_text(json.dumps(evidence, sort_keys=True))
    print('REPOSITORY_RELEASE_INTENT=PASS')


if __name__ == '__main__':
    main()
