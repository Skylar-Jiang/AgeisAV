"""Harmless event descriptions only: no command in these fixtures is executed."""
import copy
import json

import pytest

from aegisav.behavior import analyze, correlate, evaluate_rule, load_rules


def event(identity=1, **fields):
    return dict(event_id=identity, provider='Microsoft-Windows-Sysmon', computer='fixture.local',
                timestamp='2026-10-19T00:00:01Z', record_id='1', fields=fields)


def test_real_sigma_matches_evidence_not_commands():
    data = event(Image=r'C:\Windows\System32\certutil.exe',
                 CommandLine='certutil -urlcache -f https://example.invalid/inert.txt',
                 ProcessGuid='{fixture-a}', ProcessId='44')
    report = analyze(json.dumps({'events': [data]}).encode())
    assert report['status'] == 'matched'
    assert report['matches'][0]['rule_id'] == '19b08b1c-861d-4e75-a1ef-ea0c1baf202b'
    assert report['matches'][0]['event_ids'] == ['e0']
    assert report['matches'][0]['author']
    assert report['coverage']['unobserved_event_ids']
    assert report['static_policy_modified'] is False


def test_xml_namespace_and_source_and_missing_fields():
    xml = b'''<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><Event><System>
    <Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID><EventRecordID>42</EventRecordID>
    <TimeCreated SystemTime="2026-10-19T00:00:02Z"/><Computer>fixture.local</Computer></System>
    <EventData><Data Name="ProcessGuid">{fixture-a}</Data><Data Name="DestinationIp">192.0.2.1</Data></EventData>
    </Event></Events>'''
    report = analyze(xml)
    assert report['events'][0]['record_id'] == '42'
    assert report['events'][0]['kind'] == 'network'
    assert 'ProcessId' in report['events'][0]['missing_fields']
    assert report['rules'][0]['status'] == 'not_observed'
    assert report['status'] == 'incomplete'


@pytest.mark.parametrize('raw', [b'ElfFile\x00', b'{bad', b'<!DOCTYPE x [<!ENTITY e "x">]><Events>&e;</Events>',
    b'<Events><Event>', json.dumps({'events': [event()] * 1001}).encode(), b' ' * (4*1024**2+1)],
    ids=['evtx','bad-json','entity','bad-xml','event-limit','size-limit'])
def test_rejects_invalid_and_bounded_input(raw):
    with pytest.raises(ValueError):
        analyze(raw)


def test_partial_errors_unsupported_events_and_foreign_provider_not_negative():
    report = analyze(json.dumps({'events': [event(999), {'event_id': 'bad'},
        dict(event(Image=r'C:\whoami.exe', CommandLine='whoami /groups'), provider='Other')]}).encode())
    assert report['status'] == 'incomplete'
    assert report['parse_errors'][0]['index'] == 1
    assert report['coverage']['unsupported_event_ids'] == [999]
    assert len(report['matches']) == 0


def test_sigma_unsupported_semantics_rejected_even_in_nonmatching_branch():
    rule = copy.deepcopy(load_rules()[0])
    rule['detection']['selection_bad'] = {'CommandLine|re': '(a+)+'}
    assert evaluate_rule(rule, event(Image='benign.exe'))['status'] == 'unsupported'
    rule['detection'].pop('selection_bad')
    rule['detection']['condition'] = 'selection_img | count() > 1'
    assert evaluate_rule(rule, event())['status'] == 'unsupported'


def test_missing_sigma_fields_are_unknown_not_false():
    rule = next(r for r in load_rules() if 'whoami' in r['title'].lower())
    assert evaluate_rule(rule, event(Image=r'C:\whoami.exe'))['status'] == 'field_incompatible'
    assert evaluate_rule(rule, event(Image='benign.exe', CommandLine='echo harmless'))['status'] == 'no_match'
    assert evaluate_rule(rule, event(Image=r'C:\whoami.exe', CommandLine='WHOAMI /GROUPS'))['status'] == 'matched'


def test_process_guid_and_host_scope_no_name_or_pid_guessing():
    rows = [event(ProcessGuid='{a}', ProcessId='4', Image='same.exe'),
            dict(event(ProcessGuid='{b}', ProcessId='4', Image='same.exe', ParentProcessGuid='{a}'), timestamp='2026-10-19T00:00:02Z'),
            event(3, ProcessId='4', DestinationIp='192.0.2.1'),
            dict(event(11, ProcessGuid='{a}'), computer='other.local')]
    report = analyze(json.dumps({'events': rows}).encode())
    nodes = report['processes']
    assert len(nodes) == 2
    assert nodes[1]['parent_id'] == nodes[0]['id']
    assert report['events'][2]['process_id'] is None
    assert report['events'][3]['process_id'] is None


def test_pid_fallback_requires_explicit_creation_termination_window():
    rows = [event(ProcessId='5', Image='harmless.exe'),
            dict(event(5, ProcessId='5'), timestamp='2026-10-19T00:00:03Z'),
            dict(event(3, ProcessId='5'), timestamp='2026-10-19T00:00:02Z'),
            dict(event(3, ProcessId='5'), timestamp='2026-10-19T00:00:04Z')]
    report = analyze(json.dumps({'events': rows}).encode())
    assert report['events'][2]['process_id'] == report['processes'][0]['id']
    assert report['events'][3]['process_id'] is None


def test_no_logs_and_rule_assets_tamper_not_safe(tmp_path):
    assert analyze(b'{"events": []}')['status'] == 'not_observed'
    with pytest.raises(ValueError, match='asset'):
        load_rules(tmp_path)


def test_termination_cannot_extend_lifetime_or_create_dead_parent_edge():
    def at(second, identity, **fields):
        return dict(event(identity, **fields), timestamp=f'2026-10-19T00:00:0{second}Z')
    rows=[at(1,1,ProcessGuid='{a}',ProcessId='4',Image='parent.exe'),
          at(4,5,ProcessGuid='{a}',ProcessId='4'), # intentionally out of record order
          at(2,5,ProcessGuid='{a}',ProcessId='4'),
          at(3,3,ProcessGuid='{a}',ProcessId='4'),
          at(3,1,ProcessGuid='{b}',ProcessId='5',ParentProcessGuid='{a}',Image='child.exe')]
    report=analyze(json.dumps({'events':rows}).encode())
    assert report['processes'][0]['end'].startswith('2026-10-19T00:00:02.')
    assert report['events'][3]['process_id'] is None
    assert report['processes'][1]['parent_id'] is None


def test_disjoint_pid_lifetimes_close_without_merging():
    def at(second, identity):
        return dict(event(identity, ProcessId='4',Image='same.exe'),timestamp=f'2026-10-19T00:00:0{second}Z')
    report=analyze(json.dumps({'events':[at(1,1),at(2,5),at(3,1),at(4,3),at(5,5)]}).encode())
    assert report['processes'][1]['end'] is not None
    assert report['events'][3]['process_id']==report['processes'][1]['id']


def test_three_valued_condition_and_unsupported_branches():
    from aegisav.behavior import condition
    selections={'selection_a':True,'selection_b':None,'filter':False}
    assert condition('(selection_a or selection_b) and not filter',selections) is True
    assert condition('all of selection_*',selections) is None
    assert condition('1 of selection_*',selections) is True
    with pytest.raises(ValueError): condition('all of missing_*',selections)
    with pytest.raises(ValueError): condition('selection_a or missing',selections)


def test_pid_fallback_cannot_discard_open_competing_guid():
    def at(second, identity, **fields):
        return dict(event(identity,ProcessId='4',**fields),timestamp=f'2026-10-19T00:00:0{second}Z')
    rows=[at(1,1,ProcessGuid='{a}'),at(3,1,ProcessGuid='{b}'),
          at(5,5,ProcessGuid='{a}'),at(4,3,DestinationIp='192.0.2.1')]
    report=analyze(json.dumps({'events':rows}).encode())
    assert report['events'][3]['process_id'] is None


def test_duplicate_fields_and_oversized_normalized_evidence_fail_closed():
    with pytest.raises(ValueError): analyze(b'{"events":[],"events":[]}')
    row=event(Image='a'*4096,CommandLine='b'*4096)
    with pytest.raises(OverflowError): analyze(json.dumps({'events':[row]*100}).encode())
    report=analyze(json.dumps({'events':[event(1.5)]}).encode())
    assert report['parse_errors'] and report['status']=='incomplete'
