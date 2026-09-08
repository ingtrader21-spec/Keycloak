import copy
import hashlib
import json
import unittest
from verify_intent import validate_plan, approved_reviewers

class IntentTests(unittest.TestCase):
    def setUp(self):
        self.plan = dict(schema="reviewed-image-publication/v1", repository="appolon1908-hue/Keycloak", source_sha="a"*40, source_tree="b"*40, image_repository="ghcr.io/appolon1908-hue/codestra-keycloak", publish_image=True, deploy_production=False, external_effects=False, sbom_required=True, provenance_required=True)
    def verify(self, plan, digest=None):
        digest = digest or hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(",",":")).encode()).hexdigest()
        validate_plan(plan,"appolon1908-hue/Keycloak","a"*40,digest)
    def test_valid(self): self.verify(self.plan)
    def test_hash_tampering(self):
        with self.assertRaises(ValueError): self.verify(self.plan,"0"*64)
    def test_source_substitution(self):
        self.plan["source_sha"]="c"*40
        with self.assertRaises(ValueError): self.verify(self.plan)
    def test_unsafe_flags(self):
        for key in ("deploy_production","external_effects"):
            plan=copy.deepcopy(self.plan);plan[key]=True
            with self.assertRaises(ValueError): self.verify(plan)
    def test_attestations_required(self):
        for key in ("sbom_required","provenance_required","publish_image"):
            plan=copy.deepcopy(self.plan);plan[key]=False
            with self.assertRaises(ValueError): self.verify(plan)
    def test_wrong_registry(self):
        self.plan["image_repository"]="ghcr.io/other/image"
        with self.assertRaises(ValueError): self.verify(self.plan)
    def test_review_independence(self):
        pr={"user":{"login":"author"},"head":{"sha":"a"*40}}
        reviews=[{"user":{"login":name,"type":"User"},"state":"APPROVED","commit_id":"a"*40} for name in ("author","pusher","reviewer")]
        self.assertEqual(approved_reviewers(pr,reviews,"pusher"),{"reviewer"})
    def test_stale_review(self):
        pr={"user":{"login":"author"},"head":{"sha":"a"*40}}
        reviews=[{"user":{"login":"reviewer","type":"User"},"state":"APPROVED","commit_id":"b"*40}]
        self.assertEqual(approved_reviewers(pr,reviews,"pusher"),set())
