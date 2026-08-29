# Old runtime preservation and retirement

Do not start the old Keycloak to inspect it. First verify free space, identify the stopped PostgreSQL volume, create checksummed cold preservation, copy it off-host and restore-test it in isolation. Inventory realms, users, groups, roles, clients, identity providers, actions, federation and signing configuration from the restored copy.

Before cutover, record every Keycloak host/container and the public traffic target. Disable obsolete automatic startup and remove it from traffic only during the approved cutover. Retain its data until recovery evidence and rollback rehearsal are accepted. Deletion is a later, separately approved action.
