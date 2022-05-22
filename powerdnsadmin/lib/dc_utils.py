import re
import traceback
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
from urllib.parse import urlencode

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
    else:
        ret["data"] = record.data
    try:
        ret["_dc"] = json.loads(record.comment)
        if "_dc" in ret and ret["_dc"] is None:
            del ret["_dc"]
    except JSONDecodeError:
        pass
    return ret


def transform_records_to_dc_format(domain_name, records):
    return [transform_record_to_dc_format(domain_name, x) for x in records]


def transform_record_to_pdns_format(domain_name, record):
    ret = {
        "type": record["type"],
        # "name": domain_name if record["name"] == "@" or record["name"] == "" else 
        #     (record["name"] if record["name"].endswith(".") else f'{record["name"]}.{domain_name}'),
        "name": record["name"],
        "ttl": record["ttl"]
    }
    if record["type"] in ['SRV']:
        ret["data"] = f'{record["priority"]} {record["weight"]} {record["port"]} {record["data"]}'
        ret["name"] = f'_{record["service"]}._{"tcp" if record["protocol"] == "TCP" else "udp"}.{record["name"]}'
    elif record["type"] in ['MX']:
        ret["data"] = f'{record["priority"]} {record["data"]}'
    else:   
        ret["data"] = record["data"]
    if record["type"] in ['TXT'] \
        and not record["data"].startswith('"') \
        and not record["data"].endswith('"'):
        ret["data"] = f'"{record["data"]}"'
    ret["comment"] = record.get("_dc", None)
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
                "record_data": x["data"],
                "record_comment": json.dumps(x["comment"]),
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
 
def add_query_params(url, params):
    url_parts = list(urlparse.urlparse(url))
    query = dict(urlparse.parse_qsl(url_parts[4]))
    query.update(params)

    url_parts[4] = urlencode(query)

    return urlparse.urlunparse(url_parts)