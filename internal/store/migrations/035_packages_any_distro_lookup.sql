-- Indexes for looking packages up by name or source name in any distro: the OSV fast path asks for
-- the packages each affected entry of a changed record names, without a distro. The distro indexes
-- of 001 cannot serve those lookups past the ecosystem, so each one read every package of the
-- ecosystem, hundreds of times for one Ubuntu kernel record.
CREATE INDEX packages_by_source_any ON packages(ecosystem, source_name, name);
CREATE INDEX packages_by_name_any ON packages(ecosystem, name);
