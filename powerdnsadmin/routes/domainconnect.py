import json
from functools import wraps
from json import JSONDecodeError
from urllib.parse import urljoin
from base64 import b64encode
from flask import (
    Blueprint, g, request, abort, current_app, make_response, jsonify,
    url_for, render_template, redirect
)
from flask_login import current_user

from ..models.base import db
from ..models import (
    Setting, Domain, Record, RecordEntry
)
from ..lib import utils, helper
from ..lib.domainconnect_schema import (
    DomainConnectSettingsSchema,
)
from ..lib.dc_utils import *

from distutils.version import StrictVersion

from ..lib.errors import (
    StructuredException,
    DomainNotExists, DomainAlreadyExists, DomainAccessForbidden,
    RequestIsNotJSON, ApiKeyCreateFail, ApiKeyNotUsable, NotEnoughPrivileges,
    AccountCreateFail, AccountUpdateFail, AccountDeleteFail,
    AccountCreateDuplicate, AccountNotExists,
    UserCreateFail, UserCreateDuplicate, UserUpdateFail, UserDeleteFail,
    UserUpdateFailEmail,
)
from ..decorators import (
    is_json, can_access_domain
)
from flask_login import login_required
from domainconnectzone import (
    DomainConnect, InvalidTemplate, DomainConnectTemplates
)

from flask_wtf.csrf import generate_csrf, validate_csrf

import secrets
import string

dc_api_bp = Blueprint('domainconnect', __name__, url_prefix='/dc')

dc_settings_schema = DomainConnectSettingsSchema()

redir_template_records = [
   {'type': 'A', 'pointsTo': '127.0.0.1', 'ttl': 600},
   {'type': 'AAAA', 'pointsTo': '::1', 'ttl': 600}
]

@dc_api_bp.before_request
def before_request():
    # Check site is in maintenance mode
    maintenance = Setting().get('maintenance')
    if (
            maintenance and current_user.is_authenticated and
            current_user.role.name not in [
        'Administrator', 'Operator'
    ]
    ):
        return make_response(
            jsonify({
                "status": False,
                "msg": "Site is in maintenance mode"
            }))


def operator_role_or_allow_user_manage_dc_templates_required(f):
    """
    Grant access if user is in Operator role or higher
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not(Setting().get('allow_user_manage_dc_templates') or current_user.role.name in ['Administrator', 'Operator']):
            abort(403)
        return f(*args, **kwargs)

    return decorated_function


'''
@api_bp.route('/pdnsadmin/zones', methods=['GET'])
@api_basic_auth
def api_login_list_zones():
    if current_user.role.name not in ['Administrator', 'Operator']:
        domain_obj_list = get_user_domains()
    else:
        domain_obj_list = Domain.query.all()

    domain_obj_list = [] if domain_obj_list is None else domain_obj_list
    return jsonify(domain_schema.dump(domain_obj_list)), 200
'''


@dc_api_bp.route('/', methods=['GET'])
def dc_api_root():
    return jsonify({}), 404


@dc_api_bp.route('/sync/', methods=['GET'])
def dc_sync_ux_root():
    return jsonify({}), 404


@dc_api_bp.route('/v2/<string:domain_name>/settings', methods=['GET'])
def dc_api_settings(domain_name):
    current_app.logger.debug(f'/settings for {domain_name}')
    domain = db.session.query(Domain).filter(Domain.name == domain_name).first()
    current_app.logger.debug(f'Domain found: {domain}')

    if not domain:
        return "{}", 404

    settings = {
        "providerId": Setting().get('dc_provider_id'),
        "providerName": Setting().get('dc_provider_name'),
        "providerDisplayName": Setting().get('dc_provider_display_name'),
        "urlSyncUX": url_for('domainconnect.dc_sync_ux_root', _external=True),
        #        "urlAsyncUX": "https://domainconnect.virtucondomains.com", //async not supported for now
        "urlAPI": url_for('domainconnect.dc_api_root', _external=True),
        "width": 750,
        "height": 750,
        "urlControlPanel": url_for("domain.domain", domain_name=domain_name, _external=True)
    }

    return jsonify(dc_settings_schema.dump(settings))


@dc_api_bp.route('/v2/domainTemplates/providers/<string:provider_id>/services/<string:service_id>', methods=['GET'])
def dc_template_discovery(provider_id, service_id):
    try:
        # TODO: protect provider_id and service_id so that path traversal won't be possible
        dc = DomainConnect(provider_id, service_id, Setting().get('dc_template_folder'),
                           redir_template_records=redir_template_records)
    except Exception as e:
        return jsonify({"error": type(e).__name__, "error_message": f"{e}"}), 404
    return jsonify(dc.data)


@dc_api_bp.route('/sync/v2/domainTemplates/providers/<string:provider_id>/services/<string:service_id>/apply',
                 methods=['GET'])
@login_required
def dc_sync_ux_apply(provider_id, service_id):
    domain_name = request.args.get('domain')
    host = request.args.get('host')
    params = dict(request.args)
    # params['fqdn'] = domain_name if host is None else f"{host}.{domain_name}"
    current_app.logger.debug(f"Apply args: {params}")
    return dc_sync_ux_apply_do(provider_id, service_id, domain_name=domain_name, host=host, params=params)


def load_records(rrsets):
    records = []
    records_allow_to_edit = Setting().get_forward_records_allow_to_edit()

    # Render the "records" to display in HTML datatable
    #
    # BUG: If we have multiple records with the same name
    # and each record has its own comment, the display of
    # [record-comment] may not consistent because PDNS API
    # returns the rrsets (records, comments) has different
    # order than its database records.
    # TODO:
    #   - Find a way to make it consistent, or
    #   - Only allow one comment for that case
    if StrictVersion(Setting().get('pdns_version')) >= StrictVersion('4.0.0'):
        for r in rrsets:
            if r['type'] in records_allow_to_edit:
                r_name = r['name'].rstrip('.')

                # If it is reverse zone and pretty_ipv6_ptr setting
                # is enabled, we reformat the name for ipv6 records.
                if Setting().get('pretty_ipv6_ptr') and r[
                    'type'] == 'PTR' and 'ip6.arpa' in r_name and '*' not in r_name:
                    r_name = dns.reversename.to_address(
                        dns.name.from_text(r_name))

                # Create the list of records in format that
                # PDA jinja2 template can understand.
                index = 0
                for record in r['records']:
                    if (len(r['comments']) > index):
                        c = r['comments'][index]['content']
                    else:
                        c = ''
                    record_entry = RecordEntry(
                        name=r_name,
                        type=r['type'],
                        status='Disabled' if record['disabled'] else 'Active',
                        ttl=r['ttl'],
                        data=record['content'],
                        comment=c,
                        is_allowed_edit=True)
                    index += 1
                    records.append(record_entry)
        return records
    else:
        # Unsupported version
        abort(500)

def dc_can_access_domain(domain_name):
    domain = Domain.query.filter(Domain.name == domain_name).first()

    if current_user.role.name not in ['Administrator', 'Operator']:
        if not domain:
            return False
        valid_access = Domain(id=domain.id).is_valid_access(
            current_user.id)
        if not valid_access:
            return False

    return True


@can_access_domain
def dc_sync_ux_apply_do(provider_id, service_id, domain_name, host, params):
    current_app.logger.debug(f'dc_sync_ux_apply_do {provider_id} {service_id} {domain_name} {params}')

    domain = Domain.query.filter(Domain.name == domain_name).first()
    if not domain:
        abort(404)

    group_ids, key, qs, sig = extract_domain_connect_params(params)

    # Query domain's rrsets from PowerDNS API
    rrsets = Record().get_rrsets(domain.name)
    # API server might be down, misconfigured
    if not rrsets:
        abort(500)
    records = load_records(rrsets)
    dc_records = transform_records_to_dc_format(domain_name, records)
    current_app.logger.debug(f'transformed RRs: {dc_records}')

    dc = DomainConnect(provider_id, service_id, Setting().get('dc_template_folder'),
                       redir_template_records=redir_template_records)
    dc_error = None
    dc_apply_result = None
    try:
        dc_apply_result = dc.apply_template(dc_records, domain_name, host, params,
                                            group_ids=group_ids,
                                            qs=qs, sig=sig, key=key, multi_aware=True)
        current_app.logger.debug(f'template apply result: {dc_apply_result}')
        dc_apply_result = (
            transform_records_to_pdns_format(domain_name, dc_apply_result[0]),
            transform_records_to_pdns_format(domain_name, dc_apply_result[1]),
            transform_records_to_pdns_format(domain_name, dc_apply_result[2]),
        )
        current_app.logger.debug(f'template apply result after transform to pdns: {dc_apply_result}')
    except Exception as e:
        dc_error = f'[{type(e).__name__}] {e}'

    return render_template('dc_apply_step1.html',
                           domain=domain,
                           records=records,
                           current_user=current_user,
                           providerId=provider_id,
                           providerName=dc.data["providerName"],
                           serviceId=service_id,
                           serviceName=dc.data["serviceName"],
                           dc_error=dc_error,
                           dc_add_records=dc_apply_result[0] if dc_apply_result is not None else None,
                           dc_delete_records=dc_apply_result[1] if dc_apply_result is not None else None,
                           dc_final_zone=dc_apply_result[2] if dc_apply_result is not None else None,
                           dc_finalize_link=f'{url_for("domainconnect.dc_sync_ux_apply_finalize", provider_id=provider_id, service_id=service_id)}'
                                            f'?{request.query_string.decode("ascii")}'
                                            f'&_csrf={generate_csrf()}'
                           )


def extract_domain_connect_params(params):
    sig = None
    key = None
    group_ids = None

    # extract DC params
    if 'sig' in params:
        sig = params['sig']
    if 'key' in params:
        key = params['key']
    if 'groupId' in params:
        group_ids = params['groupId'].split(',')

    qs = None
    split = request.query_string.decode('ascii').split('&')
    for param in split:
        if not param.startswith('sig=') and not param.startswith('key=') and not param.startswith('_csrf='):
            if not qs:
                qs = param
            else:
                qs = qs + '&' + param
    return group_ids, key, qs, sig


@dc_api_bp.route('/sync/v2/domainTemplates/providers/<string:provider_id>/services/<string:service_id>/apply-finalize',
                 methods=['GET'])
@login_required
def dc_sync_ux_apply_finalize(provider_id, service_id):
    domain_name = request.args.get('domain')
    host = request.args.get('host')
    csrf = request.args.get('_csrf')
    current_app.logger.debug(f"csrf: {csrf}")
    params = dict(request.args)
    del params['_csrf']
    try:
        validate_csrf(csrf)
    except:
        return redirect(url_for('domainconnect.dc_sync_ux_apply', provider_id=provider_id,
                                service_id=service_id, **params))
    return dc_sync_ux_apply_do_finalize(provider_id, service_id, domain_name=domain_name, host=host, params=params)


@can_access_domain
def dc_sync_ux_apply_do_finalize(provider_id, service_id, domain_name, host, params):
    current_app.logger.debug(f'dc_sync_ux_apply_do_finalize {provider_id} {service_id} {domain_name} {params}')

    domain = Domain.query.filter(Domain.name == domain_name).first()
    if not domain:
        abort(404)

    # Query domain's rrsets from PowerDNS API
    rrsets = Record().get_rrsets(domain.name)
    # API server might be down, misconfigured
    if not rrsets:
        abort(500)
    records = load_records(rrsets)
    dc_records = transform_records_to_dc_format(domain_name, records)
    current_app.logger.debug(f'transformed RRs: {dc_records}')

    group_ids, key, qs, sig = extract_domain_connect_params(params)

    dc_error = None
    dc_apply_result = None
    try:
        dc = DomainConnect(provider_id, service_id, Setting().get('dc_template_folder'),
                           redir_template_records=redir_template_records)
        dc_apply_result = dc.apply_template(dc_records, domain_name, host, params,
                                            group_ids=group_ids,
                                            qs=qs, sig=sig, key=key, multi_aware=True)
        current_app.logger.debug(f'template apply result: {dc_apply_result}')
        dc_apply_result = (
            transform_records_to_pdns_format(domain_name, dc_apply_result[0]),
            transform_records_to_pdns_format(domain_name, dc_apply_result[1]),
            transform_records_to_pdns_format(domain_name, dc_apply_result[2]),
        )
        current_app.logger.debug(f'template apply result after transform to pdns: {dc_apply_result}')
        apply_dc_template_to_zone(domain_name, dc_apply_result, provider_id,
                                  service_id, host, current_user.username, domain.id)
        rrsets = Record().get_rrsets(domain.name)
        records = load_records(rrsets)
    except Exception as e:
        dc_error = f'[{type(e).__name__}] {e}'

    return render_template('dc_apply_step2.html',
                           domain=domain,
                           records=records,
                           current_user=current_user,
                           providerId=provider_id,
                           providerName=dc.data["providerName"],
                           serviceId=service_id,
                           serviceName=dc.data["serviceName"],
                           dc_error=dc_error,
                           dc_redirect_link=add_query_params(
                               params["redirect_uri"],
                               dict(filter(lambda val: val[0] == "state", params.items()))
                           ) if "redirect_uri" in params else None
                           )


@dc_api_bp.route('/admin/templates', methods=['GET'])
@dc_api_bp.route('/admin/templates/list', methods=['GET'])
@operator_role_or_allow_user_manage_dc_templates_required
@login_required
def templates():
    current_app.jinja_env.globals.update(can_access_domain=dc_can_access_domain)
    templlist = DomainConnectTemplates(template_path=Setting().get('dc_template_folder'))
    return render_template('dc_template.html', templates=templlist.templates)


@dc_api_bp.route('/admin/templates/providers/<string:provider_id>/services/<string:service_id>', methods=['POST'])
@dc_api_bp.route('/admin/templates/new', methods=['POST'])
@operator_role_or_allow_user_manage_dc_templates_required
@login_required
def template_edit_post(provider_id=None, service_id=None):
    current_app.jinja_env.globals.update(can_access_domain=dc_can_access_domain)
    try:
        result = None
        error = None
        templateerror = None
        variables = {}
        templ = templ = {
            "providerId": None,
            "serviceId": None,
            "records": []
        }
        templ = json.loads(request.form["_template"])
        templlist = DomainConnectTemplates(template_path=Setting().get('dc_template_folder'))
        templlist.validate_template(templ)
        try:
            variables = DomainConnectTemplates.get_variable_names(templ, request.form)
        except InvalidTemplate as tex:
            templateerror = f"{tex}"

        if request.form["_test_template"] == "true":
            try:
                templlist.validate_template(templ)
                dc = DomainConnect(templ["providerId"], templ["serviceId"], template=templ,
                                   redir_template_records=redir_template_records)
                dc_apply_result = dc.apply_template(zone_records=[], domain=request.form["domain"],
                                                    host=request.form["host"],
                                                    group_ids=request.form.getlist('group'),
                                                    params=request.form, ignore_signature=True, multi_aware=True)
                result = transform_records_to_pdns_format(request.form["domain"], dc_apply_result[2])
            except Exception as e:
                error = f"{e}"
    except JSONDecodeError as jex:
        templateerror = f"Invalid JSON format: {jex}"
    except Exception as gex:
        templateerror = f"Template validation error: {gex}"
    return render_template('dc_template_edit.html', new=service_id is None or provider_id is None,
                           template_raw=request.form["_template"], template=templ,
                           params=variables,
                           groups=DomainConnectTemplates.get_group_ids(templ),
                           group_values=request.form.getlist('group'),
                           records=result, error=error, templateerror=templateerror)


@dc_api_bp.route('/admin/templates/providers/<string:provider_id>/services/<string:service_id>', methods=['GET'])
@operator_role_or_allow_user_manage_dc_templates_required
@login_required
def template_edit(provider_id, service_id):
    current_app.jinja_env.globals.update(can_access_domain=dc_can_access_domain)
    dc = DomainConnect(provider_id, service_id, template_path=Setting().get('dc_template_folder'),
                       redir_template_records=redir_template_records)
    template = dc.data
    return render_template('dc_template_edit.html', new=False, template=template,
                           params=DomainConnectTemplates.get_variable_names(template, {'domain': 'example.com'}),
                           groups=DomainConnectTemplates.get_group_ids(template))


@dc_api_bp.route('/admin/templates/new', methods=['GET'])
@operator_role_or_allow_user_manage_dc_templates_required
@login_required
def template_new():
    current_app.jinja_env.globals.update(can_access_domain=dc_can_access_domain)
    template = {
        "providerId": "<Enter providerId>",
        "providerName": "<Enter providerName>",
        "serviceId": "<Enter serviceId>",
        "serviceName": "<Enter serviceName>",
        "version": 1,
        "logoUrl": "<Enter logoUrl>",
        "description": "<Enter description>",
        "variableDescription": "<Enter variableDescription>",
        "syncBlock": False,
        "syncPubKeyDomain": "<Enter syncPubKeyDomain>",
        "syncRedirectDomain": "<Enter syncRedirectDomain>",
        "warnPhishing": True,
        "hostRequired": False,
        "records": [
            {
                "type": "A",
                "host": "@",
                "pointsTo": "1.1.1.1",
                "ttl": 3600
            },
            {
                "type": "A",
                "host": "@",
                "pointsTo": "%a%",
                "ttl": 3600
            },
            {
                "type": "CNAME",
                "host": "www",
                "pointsTo": "@",
                "ttl": 3600
            },
            {
                "type": "CNAME",
                "host": "sub",
                "pointsTo": "%sub%.mydomain.com",
                "ttl": 3600
            },
            {
                "type": "CNAME",
                "host": "%cnamehost%",
                "pointsTo": "%sub%.mydomain.com",
                "ttl": 3600
            },
            {
                "type": "TXT",
                "host": "@",
                "data": "%txt%",
                "ttl": 3600
            },
            {
                "type": "SPFM",
                "host": "@",
                "spfRules": "include:spf.mydomain.com"
            },
            {
                "type": "MX",
                "host": "@",
                "pointsTo": "1.1.1.2",
                "priority": 0,
                "ttl": 3600
            },
            {
                "type": "MX",
                "host": "@",
                "pointsTo": "%mx%",
                "priority": 0,
                "ttl": 3600
            },
            {
                "type": "SRV",
                "service": "_sip",
                "protocol": "_tls",
                "port": 443,
                "weight": 20,
                "priority": 10,
                "name": "@",
                "target": "%target%",
                "ttl": 3600
            }
        ]
    }
    return render_template('dc_template_edit.html', new=True, template=template,
                           params=DomainConnectTemplates.get_variable_names(template, {'domain': 'example.com'}),
                           groups=DomainConnectTemplates.get_group_ids(template))


@dc_api_bp.route('/admin/templates/providers/<string:provider_id>/services/<string:service_id>/save', methods=['POST'])
@operator_role_or_allow_user_manage_dc_templates_required
@login_required
@is_json
def template_save(provider_id, service_id):
    templ = request.json["template"]
    if templ['providerId'] != provider_id or templ['serviceId'] != service_id:
        return jsonify({
                           "msg": f"ProviderId/ServiceId mismatch. Should have been: {provider_id} / {service_id}; "
                                  f"was {templ['providerId']} / {templ['serviceId']}"}), 403
    if not dc_can_access_domain(templ['providerId']):
        return jsonify({"msg": f"No access to domain {templ['providerId']}."}), 403

    current_app.logger.info(f'Template to save: {templ}')
    templlist = DomainConnectTemplates(template_path=Setting().get('dc_template_folder'))
    try:
        templlist.update_template(templ)
        return jsonify({"msg": f"Template {provider_id} / {service_id} saved successfully."}), 201
    except Exception as e:
        return jsonify({"msg": f"{e}"}), 500


@dc_api_bp.route('/admin/templates/new/save', methods=['POST'])
@operator_role_or_allow_user_manage_dc_templates_required
@login_required
@is_json
def template_save_new():
    templ = request.json["template"]

    current_app.logger.info(f'Template to save: {templ}')
    templlist = DomainConnectTemplates(template_path=Setting().get('dc_template_folder'))
    try:
        if not dc_can_access_domain(templ['providerId']):
            return jsonify({"msg": f"No access to domain {templ['providerId']}."}), 403
        templlist.create_template(templ)
        return jsonify({"msg": f"Template {templ['providerId']} / {templ['serviceId']} saved successfully.",
                        "nextUrl": url_for("domainconnect.template_edit", provider_id=templ['providerId'],
                                           service_id=templ['serviceId'])}), 201
    except Exception as e:
        return jsonify({"msg": f"{e}"}), 500
