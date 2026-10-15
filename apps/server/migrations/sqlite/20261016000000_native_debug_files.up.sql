CREATE TABLE native_debug_file (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    checksum TEXT NOT NULL,
    object_index INTEGER NOT NULL,
    debug_id TEXT NOT NULL,
    arch TEXT NOT NULL,
    file_format TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    file_name TEXT NOT NULL,
    metadata TEXT NOT NULL,
    PRIMARY KEY (project_id, checksum, object_index)
);
CREATE INDEX native_debug_file_lookup ON native_debug_file(project_id, debug_id, arch);
CREATE TABLE native_chunk_owner (
    checksum TEXT NOT NULL REFERENCES chunk(checksum) ON DELETE CASCADE,
    actor TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (checksum, actor)
);
