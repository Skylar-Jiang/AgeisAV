"""Teaching evidence adapter. Imported claims remain distinct from fresh scans."""
import copy
import hashlib
import html
import json
from pathlib import Path
import re

from .pe import validate_pe

ENGINES = ('sha256', 'fuzzy', 'yara_x', 'clamav', 'lightgbm')
LIMIT = 16 * 1024**2


def pe_details(data):
    """Only call for untrusted PE inside the existing disposable scan worker."""
    import pefile
    if len(data) > LIMIT:
        raise ValueError('Teaching static parser retains product16MiB limit')
    validate_pe(data)
    with pefile.PE(data=data, fast_load=True) as pe:
        pe.parse_data_directories(directories=[1, 0])
        header = {key: int(getattr(pe.FILE_HEADER, field)) for key, field in
                  (('machine', 'Machine'), ('section_count', 'NumberOfSections'),
                   ('timestamp_untrusted', 'TimeDateStamp'), ('characteristics', 'Characteristics'))}
        header.update({key: int(getattr(pe.OPTIONAL_HEADER, field)) for key, field in
                       (('magic', 'Magic'), ('entry_point_rva', 'AddressOfEntryPoint'),
                        ('image_base', 'ImageBase'), ('image_size', 'SizeOfImage'),
                        ('subsystem', 'Subsystem'), ('dll_characteristics', 'DllCharacteristics'))})
        text = lambda value: (value or b'').decode('utf-8', errors='replace')[:256]
        sections = [{'name': text(s.Name.rstrip(b'\0')), 'virtual_address': s.VirtualAddress,
                     'virtual_size': s.Misc_VirtualSize, 'raw_offset': s.PointerToRawData,
                     'raw_size': s.SizeOfRawData, 'characteristics': s.Characteristics,
                     'entropy': round(s.get_entropy(), 6)} for s in pe.sections]
        imports = []
        total = 0
        for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
            for symbol in entry.imports:
                total += 1
                if len(imports) < 2048:
                    imports.append({'dll': text(entry.dll), 'name': text(symbol.name),
                                    'ordinal': symbol.ordinal, 'address': symbol.address})
        symbols = getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])
        exports = [{'name': text(s.name), 'ordinal': s.ordinal, 'address': s.address,
                    'forwarder': text(s.forwarder)} for s in symbols[:2048]]
        # Strings are clues, never executable commands or an independent verdict.
        matches = re.finditer(rb'[\x20-\x7e]{6,160}', data)
        clues = []
        pattern = re.compile(r'https?://|powershell|cmd\.exe|CreateRemoteThread|WriteProcessMemory|'
                             r'VirtualAlloc|CreateService|\\CurrentVersion\\Run', re.I)
        for match in matches:
            value = match.group().decode('ascii')
            if pattern.search(value):
                clues.append({'offset': match.start(), 'text': value})
                if len(clues) == 128:
                    break
        return {'header': header, 'sections': sections, 'imports': imports, 'exports': exports,
                'function_counts': {'imports': total, 'exports': len(symbols)},
                'functions_truncated': total > 2048 or len(symbols) > 2048,
                'strings': {'heuristic_only': True, 'encoding': 'ASCII', 'limit': 128,
                            'possibly_truncated': len(clues) == 128, 'clues': clues},
                'parser_warnings': pe.get_warnings()[:32]}


def attach_scan(sample, report):
    if not sample.get('sha256') or sample['sha256'] != report.get('sha256'):
        raise ValueError('Static scan identity does not match the evidence sample')
    sample['aegisav_scan'] = copy.deepcopy(report)
    sample['engines'] = {name: copy.deepcopy(report.get('engines', {}).get(name,
                        {'status': 'not_observed', 'evidence': []})) for name in ENGINES}


def _markdown(row):
    safe = lambda value: html.escape(str(value)).replace('`', '\\`').replace('[', '\\[')
    lines = [f"# 教学样本 {safe(row['sample_id'])}：{safe(row['name'])}", '',
             f"SHA256：{safe(row.get('sha256') or '未确认')}",
             f"来源：{safe(row.get('source', '未提供'))}",
             f"文件大小：{safe(row.get('size_bytes', '未记录'))}", '',
             '## 证据性质', '', '历史截图/章节是来源材料，不表示本轮重新扫描或已独立验证身份。',
             'Defender结果只来自导入证据；没有在本机对真实恶意样本调用Defender。', '',
             '## Microsoft Defender 原始证据', '',
             f"状态：{row['defender']['status']}；身份独立验证：false", '']
    for evidence in row['evidence']:
        lines += [f"- [{safe(evidence.get('kind', 'other'))}]({evidence['path']})；"
                  f"身份关联：{safe(evidence.get('identity_binding', 'not_verified'))}；"
                  f"SHA256：{evidence['sha256']}"]
    lines += ['', '## PE头、节、函数及字符串', '',
              '新解析结果见JSON的pe_details；没有原件时保留历史章节及截图，不填造结构或模糊哈希。',
              '', '## 逐引擎状态', '', '| 引擎 | 状态 |', '| --- | --- |']
    for name, engine in row['engines'].items():
        lines.append(f"| {name} | {safe(engine['status'])} |")
    lines += ['', '完整哈希、引擎证据、分数、版本及裁决原样保存在同名JSON；未观察不代表阴性。',
              '', '## 分析结论与未完成项', '', safe(row.get('conclusion', '待分析者填写，不能从未命中推断安全。'))]
    lines += ['- ' + safe(item) for item in row['missing']]
    for key, title in (('historical_static_metadata', '历史结构记录（来源转录）'),
                       ('pe_details', '本次受限静态解析'), ('aegisav_scan', '完整引擎报告')):
        if key in row:
            lines += ['', '## ' + title, '', '```json',
                      json.dumps(row[key], ensure_ascii=False, indent=2).replace('`', '\\u0060'), '```']
    if row.get('legacy_text'):
        lines += ['', '## 历史章节原文（未经重新验证）', '', '```tex',
                  row['legacy_text'].replace('`', '\\u0060'), '```']
    return '\n'.join(lines) + '\n'


def export_workbook(manifest, source_root, output):
    """Validate the whole input before creating a fresh private evidence bundle."""
    source_root, output = Path(source_root).resolve(), Path(output).resolve()
    if output.exists():
        raise FileExistsError('Refuse to overwrite an evidence bundle')
    if manifest.get('schema') != 1 or not 1 <= len(manifest.get('samples', [])) <= 5:
        raise ValueError('Expected one to five teaching slots, schema1')
    rows, payloads, ids = [], [], set()
    evidence_bytes = 0
    for original in manifest['samples']:
        row = copy.deepcopy(original)
        sample_id = str(row['sample_id'])
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,32}', sample_id) or sample_id in ids:
            raise ValueError('Invalid or duplicate sample ID')
        ids.add(sample_id)
        sha = row.get('sha256')
        if sha is not None and not re.fullmatch('[0-9a-f]{64}', sha):
            raise ValueError('Invalid sample SHA256')
        row.setdefault('name', sample_id)
        row.setdefault('missing', [])
        row['engines'] = {name: {'status': 'not_observed', 'evidence': []} for name in ENGINES}
        row['defender'] = {'status': 'not_provided', 'identity_verified': False}
        row.setdefault('evidence', [])
        for index, evidence in enumerate(row['evidence']):
            path = (source_root / evidence['path']).resolve()
            if not path.is_relative_to(source_root) or path.suffix.lower() not in {'.png', '.jpg', '.jpeg', '.txt', '.json', '.xml', '.tex'}:
                raise ValueError('Evidence path/type is not allowed')
            if evidence_bytes + path.stat().st_size > 128 * 1024**2:
                raise ValueError('Evidence bundle exceeds128MiB')
            with path.open('rb') as stream:
                data = stream.read(LIMIT + 1)
            if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != evidence['sha256']:
                raise ValueError('Evidence size or SHA256 mismatch')
            evidence_bytes += len(data)
            if evidence_bytes > 128 * 1024**2:
                raise ValueError('Evidence bundle exceeds128MiB')
            if (data.startswith(b'MZ') or
                    (path.suffix.lower() == '.png' and not data.startswith(b'\x89PNG\r\n\x1a\n')) or
                    (path.suffix.lower() in {'.jpg', '.jpeg'} and not data.startswith(b'\xff\xd8\xff'))):
                raise ValueError('Executable or mislabeled image is not evidence')
            name = f'evidence/{sample_id}-{index:03d}{path.suffix.lower()}'
            evidence['original_reference'] = evidence['path']
            evidence['path'] = name
            payloads.append((name, data))
            if evidence.get('kind') == 'defender':
                row['defender']['status'] = 'imported_historical_evidence'
        if 'aegisav_scan' in row:
            attach_scan(row, row['aegisav_scan'])
        rows.append(row)
    output.mkdir(parents=True, mode=0o700)
    (output / 'evidence').mkdir(mode=0o700)
    for name, data in payloads:
        (output / name).write_bytes(data)
    for row in rows:
        (output / f"sample-{row['sample_id']}.json").write_text(json.dumps(row, ensure_ascii=False, indent=2), encoding='utf-8')
        (output / f"sample-{row['sample_id']}.md").write_text(_markdown(row), encoding='utf-8')
    index = {'schema': 1, 'source_kind': manifest.get('source_kind', 'user_import'),
             'sample_count': len(rows), 'executes_input': False,
             'raw_PE_used': manifest.get('source_kind') == 'fresh_static_analysis',
             'reports': [f"sample-{r['sample_id']}.md" for r in rows]}
    (output / 'index.json').write_text(json.dumps(index, indent=2), encoding='utf-8')
    return index
