CREATE TABLE cache_metadata (id INTEGER PRIMARY KEY CHECK(id=1), kind TEXT NOT NULL, version INTEGER NOT NULL);
CREATE TABLE documents (digest TEXT PRIMARY KEY, value BLOB NOT NULL, sequence INTEGER NOT NULL UNIQUE);
INSERT INTO cache_metadata VALUES(1,'redevplugin_release_documents',1);
