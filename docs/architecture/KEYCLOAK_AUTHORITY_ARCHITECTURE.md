# Keycloak authority architecture

The sole desired-state authority is `github.com/appolon1908-hue/Keycloak`. Production is an exact, clean `main` checkout at `/srv/keycloak`; its remote, branch, commit, file permissions, SSH host key and runtime paths are verified before deployment. A merge validates state but never mutates Keycloak.

The release path is: protected change → source and merge-result CI → exact merged SHA → non-mutating CHECK → reviewed plan hash → protected-environment approval → race-safe APPLY → convergence and OIDC evidence. Client and realm writes are limited to managed fields. Manually edited server files and `/srv/codestra-platform` are not authorities.

Production activation remains blocked until the old database is preserved and restore-tested, the public authority host is unambiguous, disk capacity is safe, and the obsolete instance cannot start or receive traffic.
