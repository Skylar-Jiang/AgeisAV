"""Bounded offline Sysmon evidence. Log text is data, never executable input."""
from collections import Counter
from datetime import datetime, timezone
import fnmatch
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

MAX_BYTES = 4*1024**2
MAX_EVENTS = 1000
RULE_ROOT = Path(__file__).resolve().parents[2]/'rules/sigma'
KINDS = {1:'process_create', 3:'network', 5:'process_end', 11:'file', 12:'registry',
         13:'registry', 14:'registry', 22:'dns', 23:'file', 26:'file', 255:'sensor_error'}
REQUIRED = {1:['ProcessGuid','ProcessId','Image','CommandLine'], 3:['ProcessGuid','ProcessId','DestinationIp'],
            5:['ProcessGuid','ProcessId'], 11:['ProcessGuid','TargetFilename'],
            12:['ProcessGuid','TargetObject'], 13:['ProcessGuid','TargetObject'],
            14:['ProcessGuid','TargetObject'], 22:['ProcessGuid','QueryName'],
            23:['ProcessGuid','TargetFilename'], 26:['ProcessGuid','TargetFilename']}


def timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z','+00:00'))
        return parsed.astimezone(timezone.utc).isoformat(timespec='microseconds') if parsed.tzinfo else None
    except ValueError:
        return None


def load_rules(root=RULE_ROOT):
    import yaml
    try:
        manifest = json.loads((root/'manifest.json').read_bytes())
        rules = []
        for row in manifest['rules']:
            path = root/row['file']
            if path.parent != root or path.suffix != '.yml':
                raise ValueError('Invalid asset path')
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != row['sha256']:
                raise ValueError('Rule asset integrity failed')
            rule = yaml.safe_load(data)
            rule.update(source=row['source'], asset_version=manifest['version'],
                        asset_sha256=row['sha256'], license=manifest['license'])
            rules.append(rule)
        if not rules:
            raise ValueError('Rule assets empty')
        return rules
    except (OSError, KeyError, ValueError, yaml.YAMLError) as error:
        raise ValueError('Sigma assets unavailable or invalid') from error


def combine(values, mode):
    # Three-valued logic: absent telemetry cannot prove a selector false.
    if mode == 'all':
        return False if False in values else None if None in values else True
    return True if True in values else None if None in values else False


def pattern(value):
    # Only Sigma string wildcards. No user-supplied regex is evaluated.
    out = ''
    i = 0
    while i < len(value):
        char = value[i]
        if char == '\\' and i+1 < len(value) and value[i+1] in '*?\\':
            i += 1
            out += re.escape(value[i])
        else:
            out += '.*' if char == '*' else '.' if char == '?' else re.escape(char)
        i += 1
    return out


def selector(node, fields):
    if isinstance(node, list) and node:
        return combine([selector(row, fields) for row in node], 'any')
    if not isinstance(node, dict) or not node:
        raise ValueError('Only nonempty field maps or lists of maps are supported')
    answers = []
    for key, raw in node.items():
        field, *mods = key.split('|')
        if any(m not in ('contains','startswith','endswith','all') for m in mods) or len(set(mods)) != len(mods):
            raise ValueError('Unsupported Sigma modifier')
        operators = [m for m in mods if m != 'all']
        if len(operators) > 1:
            raise ValueError('Unsupported modifier chain')
        values = raw if isinstance(raw, list) else [raw]
        if not values or any(not isinstance(v, str) or len(v)>4096 for v in values):
            raise ValueError('Only bounded string values supported')
        expressions = [pattern(v.casefold()) for v in values]
        if field not in fields:
            answers.append(None)
            continue
        actual = fields[field].casefold()
        op = operators[0] if operators else 'exact'
        matches = [bool(re.fullmatch(('.*' if op in ('contains','endswith') else '')+p+
                                    ('.*' if op in ('contains','startswith') else ''), actual, re.DOTALL)) for p in expressions]
        answers.append(combine(matches,'all' if 'all' in mods else 'any'))
    return combine(answers, 'all')


def condition(expression, selections):
    if not isinstance(expression, str) or len(expression)>1024:
        raise ValueError('Unsupported Sigma condition')
    tokens = re.findall(r'[A-Za-z0-9_*]+|[()]', expression)
    if ''.join(tokens) != re.sub(r'\s+', '', expression):
        raise ValueError('Unsupported Sigma condition')
    position = 0
    def atom():
        nonlocal position
        if position >= len(tokens):
            raise ValueError('Incomplete condition')
        token = tokens[position]; position += 1
        if token == 'not':
            value = atom()
            return None if value is None else not value
        if token == '(':
            value = chain('or')
            if position >= len(tokens) or tokens[position] != ')':
                raise ValueError('Unclosed condition')
            position += 1
            return value
        if token in ('all','1'):
            if position+1 >= len(tokens) or tokens[position] != 'of':
                raise ValueError('Unsupported quantifier')
            names = tokens[position+1]; position += 2
            keys = list(selections) if names=='them' else [k for k in selections if fnmatch.fnmatchcase(k,names)]
            if not keys:
                raise ValueError('No matching selectors')
            return combine([selections[k] for k in keys], 'all' if token=='all' else 'any')
        if token not in selections:
            raise ValueError('Unknown selector')
        return selections[token]
    def chain(operator):
        nonlocal position
        values = [chain('and') if operator=='or' else atom()]
        while position < len(tokens) and tokens[position] == operator:
            position += 1
            values.append(chain('and') if operator=='or' else atom())
        return combine(values,'any' if operator=='or' else 'all')
    result = chain('or')
    if position != len(tokens):
        raise ValueError('Unsupported condition tail')
    return result


def evaluate_rule(rule, event):
    try:
        if rule['logsource'] != {'category':'process_creation','product':'windows'}:
            raise ValueError('Unsupported logsource')
        detection = rule['detection']
        selections = {name:selector(value, event.get('fields',{})) for name,value in detection.items() if name!='condition'}
        value = condition(detection['condition'], selections)
    except (KeyError, TypeError, ValueError) as error:
        return dict(status='unsupported', reason=str(error))
    return dict(status='field_incompatible' if value is None else 'matched' if value else 'no_match')


def parse(data):
    if len(data)>MAX_BYTES:
        raise ValueError('Behavior log exceeds 4 MiB')
    try:
        text = data.decode('utf-8-sig')
        if '\x00' in text or '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
            raise ValueError('UTF-8 only; XML DTD/entities and EVTX are not supported')
        if text.lstrip().startswith('<'):
            root = ET.fromstring(text)
            def local(tag): return tag.rsplit('}',1)[-1]
            if local(root.tag) not in ('Events','Event'):
                raise ValueError('Expected Sysmon Event or Events XML')
            rows = []
            for node in ([root] if local(root.tag)=='Event' else list(root)):
                if local(node.tag) != 'Event':
                    raise ValueError('Unexpected XML element')
                system = next((x for x in node if local(x.tag)=='System'), None)
                values = {local(x.tag):x for x in system} if system is not None else {}
                def val(name): return values[name].text if name in values else None
                fields = {}
                for container in node:
                    if local(container.tag)=='EventData':
                        for x in container:
                            name = x.attrib.get('Name')
                            if name in fields:
                                raise ValueError('Duplicate XML event field')
                            fields[name] = x.text or ''
                rows.append(dict(event_id=val('EventID'), record_id=val('EventRecordID'),
                    computer=val('Computer'), timestamp=values.get('TimeCreated',ET.Element('x')).get('SystemTime'),
                    provider=values.get('Provider',ET.Element('x')).get('Name'), fields=fields))
                if len(rows)>MAX_EVENTS:
                    raise ValueError('Behavior event limit 1000 exceeded')
            return rows, 'sysmon_xml'
        def unique(pairs):
            result = {}
            for key,value in pairs:
                if key in result:
                    raise ValueError('Duplicate JSON field')
                result[key]=value
            return result
        body = json.loads(text, object_pairs_hook=unique)
        if not isinstance(body,dict) or set(body)!={'events'} or not isinstance(body['events'],list):
            raise ValueError('Expected normalized JSON object with events array')
        if len(body['events'])>MAX_EVENTS:
            raise ValueError('Behavior event limit 1000 exceeded')
        return body['events'], 'sysmon_json_v1'
    except (UnicodeError, ET.ParseError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError('Invalid UTF-8 Sysmon XML / normalized JSON; EVTX must be exported first') from error


def correlate(events):
    nodes = []
    for e in events:
        if e['event_id']==1 and e['computer'] and e['timestamp']:
            f = e['fields']
            nodes.append(dict(id='p'+str(len(nodes)), computer=e['computer'], guid=f.get('ProcessGuid'),
                pid=f.get('ProcessId'), image=f.get('Image'), start=e['timestamp'], end=None,
                parent_id=None, event_ids=[e['id']], creation_event=e['id'], hashes=f.get('Hashes','')))
    def candidates(e, guid, pid):
        if not e['computer'] or not e['timestamp']:
            return []
        return [n for n in nodes if n['computer'].casefold()==e['computer'].casefold() and
                ((guid and n['guid'] and n['guid'].casefold()==guid.casefold() and (not pid or not n['pid'] or pid==n['pid'])) or
                 (not guid and pid and n['pid']==pid)) and n['start']<=e['timestamp']]
    for e in sorted(events,key=lambda row:row['timestamp'] or ''):
        if e['event_id']==5:
            found = candidates(e,e['fields'].get('ProcessGuid'),e['fields'].get('ProcessId'))
            found = [n for n in found if n['end'] is None]
            if len(found)==1:
                found[0]['end']=e['timestamp']
    for e in events:
        f=e['fields']; guid=f.get('ProcessGuid')
        found=candidates(e,guid,f.get('ProcessId'))
        found=[n for n in found if not n['end'] or e['timestamp']<=n['end']]
        if not guid and len(found)==1 and not found[0]['end']:
            found=[]
        e['process_id']=found[0]['id'] if len(found)==1 else None
        if len(found)==1:
            n=found[0]
            if e['id'] not in n['event_ids']:
                n['event_ids'].append(e['id'])
            if e['event_id']==1 and f.get('ParentProcessGuid'):
                parents=candidates(e,f['ParentProcessGuid'],None)
                parents=[p for p in parents if p is not n and p['start']<n['start'] and
                         (not p['end'] or n['start']<=p['end'])]
                if len(parents)==1:
                    n['parent_id']=parents[0]['id']
    return nodes


def analyze(data, rules=None):
    rows, source_format = parse(data)
    events=[]; errors=[]; normalized_bytes=0
    for index,row in enumerate(rows):
        try:
            if not isinstance(row,dict) or isinstance(row.get('event_id'),bool):
                raise ValueError('Invalid event object')
            raw_id=row['event_id']
            if not isinstance(raw_id,(str,int)) or not str(raw_id).isdigit():
                raise ValueError('Event ID must be an integer')
            identity=int(raw_id)
            fields=row.get('fields',{})
            if not isinstance(fields,dict) or len(fields)>64 or any(not isinstance(k,str) or len(k)>128 or
                not isinstance(v,str) or len(v)>4096 for k,v in fields.items()):
                raise ValueError('Invalid or oversized event fields')
            for key in ('computer','provider','record_id','timestamp'):
                if row.get(key) is not None and (not isinstance(row[key],str) or len(row[key])>256):
                    raise ValueError('Invalid event metadata')
            time=timestamp(row.get('timestamp'))
            missing=[key for key in REQUIRED.get(identity,[]) if not fields.get(key)]
            missing += [key for key in ('computer','provider') if not row.get(key)]
            if not time: missing.append('timestamp_with_timezone')
            e=dict(id='e'+str(index), input_index=index, event_id=identity, record_id=row.get('record_id'),
                provider=row.get('provider'), computer=row.get('computer'), timestamp=time,
                timestamp_raw=row.get('timestamp'), fields=fields, kind=KINDS.get(identity,'unsupported'),
                missing_fields=missing, process_id=None)
            normalized_bytes+=len(json.dumps(e,ensure_ascii=False).encode())
            if normalized_bytes>768*1024:
                raise OverflowError('Normalized evidence exceeds 768 KiB; split the log')
            events.append(e)
        except (KeyError, TypeError, ValueError) as error:
            errors.append(dict(index=index, reason=str(error)[:160]))
    sysmon=[e for e in events if e['provider']=='Microsoft-Windows-Sysmon']
    processes=correlate(sysmon)
    matches=[]; results=[]
    try:
        rules=load_rules() if rules is None else rules
        rules_error=None
    except ValueError as error:
        rules=[]; rules_error=str(error)
    for rule in rules:
        compatible=[e for e in sysmon if e['event_id']==1]
        statuses=Counter(); ids=[]
        # Validate even when there are no compatible events.
        validation=evaluate_rule(rule,{'fields':{}})
        if validation['status']=='unsupported':
            statuses['unsupported']=1
        else:
            for e in compatible:
                state=evaluate_rule(rule,e)['status']; statuses[state]+=1
                if state=='matched': ids.append(e['id'])
        state=('unsupported' if statuses['unsupported'] else 'matched' if ids else
               'field_incompatible' if statuses['field_incompatible'] else 'no_match' if compatible else 'not_observed')
        result=dict(rule_id=rule['id'], title=rule['title'], level=rule.get('level'), author=rule.get('author'),
            source=rule.get('source'), license=rule.get('license'), asset_version=rule.get('asset_version'),
            asset_sha256=rule.get('asset_sha256'), status=state, event_statuses=dict(statuses),
            reason=validation.get('reason'), event_ids=ids)
        results.append(result)
        if ids: matches.append(result)
    observed=sorted({e['event_id'] for e in sysmon})
    incomplete=bool(errors or len(sysmon)!=len(events) or any(e['missing_fields'] or e['kind'] in ('unsupported','sensor_error') for e in events) or
                    any(r['status'] in ('unsupported','field_incompatible') for r in results))
    status='unavailable' if rules_error else 'incomplete' if incomplete else 'matched' if matches else 'no_match' if any(e['event_id']==1 for e in sysmon) else 'not_observed'
    return dict(schema=1, parser_version='sysmon-offline-v1', status=status,
        source=dict(sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data), format=source_format),
        static_policy_modified=False, events=events, processes=processes, matches=matches, rules=results,
        rules_error=rules_error, parse_errors=errors,
        coverage=dict(input_events=len(rows), parsed_events=len(events), sysmon_events=len(sysmon),
            observed_event_ids=observed, unsupported_event_ids=sorted(set(observed)-set(KINDS)),
            unobserved_event_ids=sorted(set(KINDS)-set(observed)),
            missing_field_events=sum(bool(e['missing_fields']) for e in events),
            sensor_configuration_known=False, completeness_proven=False),
        limits=dict(max_bytes=MAX_BYTES,max_events=MAX_EVENTS,normalized_evidence_bytes=768*1024),
        correlation_policy='host-guid-time-v1; pid fallback only inside unique explicit closed lifetime',
        interpretation='Rule matches are reviewable behavior signals, not proof of malware; missing events do not prove safety')
