import re
import gzip
import hmac
import hashlib
import traceback
from base64 import b64encode, b64decode
from datetime import datetime, timezone
from flask import (
    jsonify, current_app
)

from ..models import (
    Record, History
)

from .utils import (
    pretty_domain_name
)
import json
import urllib.parse as urlparse
from urllib.parse import urlencode, quote

class DomainConnectApplyException(Exception):
    pass

def convert_record_name_to_relative(domain_name, record):
    if record == domain_name:
        return "@"
    elif record.endswith(domain_name):
        return record[0:len(record) - len(domain_name) - 1]
    else:
        return record


def transform_record_to_dc_format(domain, record):
    ret = {
        "type": record.type,
        "name": convert_record_name_to_relative(domain, record.name),
        "ttl": record.ttl,
    }
    if record.type in ['SRV']:
        srvregex = re.search('([0-9]+)[ ]+([0-9]+)[ ]+([0-9]+)[ ]+([a-z][.a-z0-9]+)', record.data)
        if srvregex is not None:
            ret = {
                **ret,
                **{
                    "priority": srvregex.group(1),
                    "weight": srvregex.group(2),
                    "port": srvregex.group(3),
                    "data": srvregex.group(4),
                }
            }
        srvhostregex = re.search("(_([a-z][a-z0-9]*))[.](_([a-z][a-z0-9]*))([.]([a-z][a-z0-9.]*))?", record.name)
        if srvhostregex is not None:
            ret = {
                **ret,
                **{
                    "name": convert_record_name_to_relative(domain, 
                        srvhostregex.group(6) if srvhostregex.group(6) is not None 
                        else domain),
                    "service": srvhostregex.group(2),
                    "protocol": srvhostregex.group(4).upper()
                }
            }
    elif record.type in ['MX']:
        mxregex = re.search('([0-9]+)[ ]+([a-z][.a-z0-9]+)', record.data)
        if mxregex is None:
            ret["data"] = record.data
        else:
            ret["priority"] = mxregex.group(1)
            ret["data"] = mxregex.group(2)
    elif record.type in ['TYPE65301', 'TYPE65302']:
        ret['type'] = f"REDIR{record.type[7:]}"
    else:
        ret["data"] = record.data
    #TODO: convert comments to _dc dict entries
    return ret


def transform_records_to_dc_format(domain_name, records):
    return [transform_record_to_dc_format(domain_name, x) for x in records]


def transform_record_to_pdns_format(domain_name, record):
    ret = {
        "type": record["type"],
        # "name": domain_name if record["name"] == "@" or record["name"] == "" else 
        #     (record["name"] if record["name"].endswith(".") else f'{record["name"]}.{domain_name}'),
        "name": record["name"],
        "ttl": record["ttl"] if "ttl" in record else 60
    }
    if record['type'] in ['REDIR301', 'REDIR302']:
        ret['type'] = f'TYPE65{record["type"][5:]}'
    if record["type"] in ['SRV']:
        ret["data"] = f'{record["priority"]} {record["weight"]} {record["port"]} {record["data"]}'
        ret["name"] = f'_{record["service"].lstrip("_")}._{record["protocol"].lstrip("_").lower()}' + \
                      (f'.{record["name"]}' if record["name"] != '@' else '')
    elif record["type"] in ['MX']:
        ret["data"] = f'{record["priority"]} {record["data"]}'
    else:   
        ret["data"] = record["data"]
    if record["type"] in ['TXT'] \
        and not record["data"].startswith('"') \
        and not record["data"].endswith('"'):
        ret["data"] = f'"{record["data"]}"'
    return ret


def transform_records_to_pdns_format(domain_name, records):
    ret = [transform_record_to_pdns_format(domain_name, x) for x in records]
    todelete = []
    for i in range(0, len(ret)-1):
        for j in range(i+1, len(ret)-1):
            if ret[i] is not ret[j] and ret[i] == ret[j]:
                todelete += [ret[j]]
    for todel in todelete:
        current_app.logger.debug(f'Removing duplicate RR: {todel}')
        ret.remove(todel)
    return ret


def apply_dc_template_to_zone(domain_name, dc_output, provider_id,
    service_id, host, username, domain_id):
    try:
        r = Record()
        submitted_record = [
            {
                "record_name": x["name"],
                "record_type": x["type"],
                "record_status": "Active",
                "record_ttl": f'{x["ttl"]}',
                "record_data": x["data"]
            } for x in dc_output[2]
        ]
        current_app.logger.debug(f'RRs to save: {submitted_record}')

        result = r.apply(domain_name, submitted_record)
        if result['status'] == 'ok':
            history = History(
                msg=f'Apply Domain Connect template {provider_id}'
                    f'/{service_id} to domain {pretty_domain_name(domain_name)}'
                    f'and host {host}',
                detail = json.dumps({
                        'domain': domain_name,
                        'add_rrests': result['data'][0]['rrsets'],
                        'del_rrests': result['data'][1]['rrsets']
                    }),
                created_by=username,
                domain_id=domain_id)
            history.add()
        else:
            history = History(
                msg=f'Failed to apply Domain Connect template {provider_id}'
                    f'/{service_id} to domain {pretty_domain_name(domain_name)}'
                    f'and host {host}',
                detail = json.dumps({
                        'domain': domain_name,
                        'msg': result['msg'],
                    }),
                created_by=username)
            history.add()
            raise DomainConnectApplyException(result)
    except Exception as e:
        current_app.logger.error(
            'Cannot apply Domain Connect record changes. Error: {0}'.format(e))
        current_app.logger.debug(traceback.format_exc())
        raise
 
def _canonical_json(obj):
    """Return a canonical JSON byte string: keys sorted recursively, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _hmac_signature(canonical_bytes):
    """Compute HMAC-SHA256 over *canonical_bytes* using the app config key.

    Returns the signature as a base64-encoded ASCII string, or None when no
    key is configured (signing/verification is skipped).
    """
    key = current_app.config.get('DC_APPLY_STATE_HMAC_KEY')
    if not key:
        return None
    key_bytes = bytes.fromhex(key) if isinstance(key, str) else key
    sig = hmac.new(key_bytes, canonical_bytes, hashlib.sha256).digest()
    return b64encode(sig).decode('ascii')


def encode_apply_state(template, zone_records, domain, host, group_ids,
                       params, ignore_signature, multi_aware, dc_apply_result,
                       testdata=None):
    """Encode DomainConnect apply inputs and result into a compact URL-safe token.

    The payload is a JSON object signed with HMAC-SHA256 (when
    DC_APPLY_STATE_HMAC_KEY is set), gzip-compressed and base64-encoded so it
    can be embedded as a single query-string parameter.

    Signature procedure:
      1. Build the payload dict (without ``_signature``).
      2. Serialise it as canonical JSON (keys sorted, no whitespace).
      3. Compute HMAC-SHA256 over the canonical bytes.
      4. Add ``_signature`` (base64 of the digest) to the payload.
      5. Re-serialise the full payload (compact, key order unspecified), compress,
         and base64-encode.
    """
    # params may be a Werkzeug ImmutableMultiDict or similar mapping; convert
    # to a plain dict of lists so it round-trips cleanly through JSON.
    if hasattr(params, 'to_dict'):
        params_serialisable = params.to_dict(flat=False)
    else:
        params_serialisable = dict(params)

    payload = {
        "template": template,
        "zone_records": zone_records,
        "domain": domain,
        "host": host,
        "group_ids": group_ids,
        "params": params_serialisable,
        "ignore_signature": ignore_signature,
        "multi_aware": multi_aware,
        "dc_apply_result": dc_apply_result,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "testdata": testdata or {},
    }

    sig = _hmac_signature(_canonical_json(payload))
    if sig is not None:
        payload["_signature"] = sig

    raw = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    compressed = gzip.compress(raw)
    return b64encode(compressed).decode('ascii')


def decode_apply_state(token, verification_required=False):
    """Decode a token produced by :func:`encode_apply_state`.

    Returns the original payload dict (``_signature`` key removed).

    Signature verification is opportunistic: if ``_signature`` is present in
    the token it is always verified, regardless of *verification_required*.
    *verification_required* additionally mandates that the signature must exist.

    Parameters
    ----------
    token:
        The base64-encoded token string.
    verification_required:
        When *True*, the ``_signature`` field must be present and valid.
        When *False*, a missing signature is accepted, but a present signature
        that fails verification still raises :class:`ValueError`.
    """
    compressed = b64decode(token)
    raw = gzip.decompress(compressed)
    payload = json.loads(raw.decode('utf-8'))

    sig = payload.pop("_signature", None)

    if verification_required and sig is None:
        raise ValueError("apply_state token has no _signature")

    if sig is not None:
        expected = _hmac_signature(_canonical_json(payload))
        if expected is None:
            raise ValueError(
                "DC_APPLY_STATE_HMAC_KEY is not configured; cannot validate signature")
        if not hmac.compare_digest(sig, expected):
            raise ValueError("apply_state token signature mismatch")

    return payload


def add_query_params(url, params):
    url_parts = list(urlparse.urlparse(url))
    query = dict(urlparse.parse_qsl(url_parts[4]))
    query.update(params)

    url_parts[4] = urlencode(query)

    return urlparse.urlunparse(url_parts)