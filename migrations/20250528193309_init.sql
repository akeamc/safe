CREATE TABLE issuers (
    identifier TEXT PRIMARY KEY,
    cert TEXT NOT NULL,
    private_key TEXT NOT NULL,
    crl BLOB
);

CREATE TABLE certificates (
    issuer TEXT NOT NULL,
    serial_number INTEGER NOT NULL,
    der BLOB NOT NULL,
    revocation_time INTEGER,
    revocation_code INTEGER,
    invalidity_date INTEGER,
    PRIMARY KEY (issuer, serial_number),
    FOREIGN KEY (issuer) REFERENCES issuers (identifier)
);
