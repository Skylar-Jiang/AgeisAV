import zipfile

from experiments.collect_official_multivendor_pe import package_members, prior_manifest_index


def test_portable_member_size_failure_is_explicit_without_extraction(tmp_path):
    package = tmp_path / 'official.zip'
    with zipfile.ZipFile(package, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('portable/tool.exe', b'MZharmless')
        archive.writestr('portable/large.dll', b'x' * 17)
        archive.writestr('readme.txt', b'not a PE candidate')
    files, failures = package_members(package, 'zip', max_pe_bytes=16)
    assert files == [('portable/tool.exe', b'MZharmless')]
    assert failures == [{'member': 'portable/large.dll', 'reason': 'pe_size_limit', 'size_bytes': 17}]
    assert sorted(p.name for p in tmp_path.iterdir()) == ['official.zip']


def test_duplicate_prior_manifests_preserve_all_evidence_locations(tmp_path):
    first = tmp_path / 'manifest1.jsonl'
    second = tmp_path / 'manifest2.jsonl'
    first.write_text('{"sha256":"abc"}\n', encoding='utf-8')
    second.write_text('{"sha256":"abc"}\n{"sha256":"def"}\n', encoding='utf-8')
    index, records = prior_manifest_index([first, second], tmp_path)
    assert index == {'abc': ['manifest1.jsonl', 'manifest2.jsonl'], 'def': ['manifest2.jsonl']}
    assert len(records) == 2
    assert all(len(record['sha256']) == 64 for record in records)


def test_standalone_installer_is_read_only_and_oversize_is_recorded(tmp_path):
    package = tmp_path / 'installer.exe'
    package.write_bytes(b'MZ' + b'x' * 20)
    files, failures = package_members(package, 'exe', max_pe_bytes=16)
    assert files == []
    assert failures[0]['reason'] == 'pe_size_limit'
    assert package.read_bytes() == b'MZ' + b'x' * 20
