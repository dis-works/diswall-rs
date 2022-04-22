CREATE TABLE data (
    'client' VARCHAR(16),
    'hostname' VARCHAR(32),
    'blacklist' INT,
    'ip' VARCHAR(40)
);

CREATE INDEX client_host ON data (client, hostname);