CREATE TABLE publisher_rights (
  publisher_passport TEXT NOT NULL,
  namespace TEXT NOT NULL,
  verification_method TEXT NOT NULL,
  verified_at TIMESTAMPTZ NOT NULL,
  receipt_hash BYTEA NOT NULL,
  PRIMARY KEY (publisher_passport, namespace)
);

CREATE INDEX publisher_rights_namespace_idx ON publisher_rights (namespace);
CREATE INDEX publisher_rights_verified_at_idx ON publisher_rights (verified_at DESC);
