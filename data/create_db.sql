CREATE TABLE data (
    'client' VARCHAR(16),
    'hostname' VARCHAR(32),
    'blacklist' INT,
    'ip' VARCHAR(40),
    'until' INT
);

CREATE INDEX client_host ON data (client, hostname);
CREATE INDEX client_bl_ip ON data (client, blacklist, ip);