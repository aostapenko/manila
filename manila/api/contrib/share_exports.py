# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import urlparse
import webob

from manila.api import extensions
from manila.api.openstack import wsgi
from manila.api import xmlutil
from manila import db
from manila.db.sqlalchemy import api as sqlalchemy_api
from manila import exception
from manila.openstack.common.gettextutils import _
from manila.openstack.common import log as logging
from manila.openstack.common import strutils


LOG = logging.getLogger(__name__)

authorize_create = extensions.extension_authorizer('compute', 'exports:create')
authorize_update = extensions.extension_authorizer('compute', 'exports:update')
authorize_show = extensions.extension_authorizer('compute', 'exports:show')
authorize_delete = extensions.extension_authorizer('compute', 'exports:delete')


def _get_subnet_params(network_info):
    values = {}
    values['id'] = network_info['subnet_id']
    values['net_id'] = network_info['net_id']
    values['fixed_ip'] = network_info['fixed_ip']
    return values

class ShareExportsController(object):

    def __init__(self, ext_mgr):
        self.ext_mgr = ext_mgr

    def create(self, req, body):
        context = req.environ['manila.context']
        authorize_create(context)
        LOG.debug(body)
        export = body['export']
        share_id = export['share_id']
        network_type = export['network_type']
        network_info = export['network_info']
        if network_type == 'private':
            try:
                values = _get_subnet_params(network_info)
                values['project_id'] = context.project_id
                subnet_ref = db.subnet_add(context, values)
            except Exception as e:
                LOG.debug(e)
                raise webob.exc.HTTPForbidden()

        return {'export': {'anana': 'ololo', 'pupupu': 'kokoko'}}

#    @wsgi.serializers(xml=QuotaTemplate)
#    def show(self, req, id):
#        context = req.environ['manila.context']
#        authorize_show(context)
#        params = urlparse.parse_qs(req.environ.get('QUERY_STRING', ''))
#        user_id = None
#        if self.ext_mgr.is_loaded('os-user-quotas'):
#            user_id = params.get('user_id', [None])[0]
#        try:
#            sqlalchemy_api.authorize_project_context(context, id)
#            return self._format_quota_set(id,
#                    self._get_quotas(context, id, user_id=user_id))
#        except exception.NotAuthorized:
#            raise webob.exc.HTTPForbidden()
#
#    @wsgi.serializers(xml=QuotaTemplate)
#    def update(self, req, id, body):
#        context = req.environ['manila.context']
#        authorize_update(context)
#        project_id = id
#
#        bad_keys = []
#
#        # By default, we can force update the quota if the extended
#        # is not loaded
#        force_update = True
#        extended_loaded = False
#        if self.ext_mgr.is_loaded('os-extended-quotas'):
#            # force optional has been enabled, the default value of
#            # force_update need to be changed to False
#            extended_loaded = True
#            force_update = False
#
#        user_id = None
#        if self.ext_mgr.is_loaded('os-user-quotas'):
#            # Update user quotas only if the extended is loaded
#            params = urlparse.parse_qs(req.environ.get('QUERY_STRING', ''))
#            user_id = params.get('user_id', [None])[0]
#
#        try:
#            settable_quotas = QUOTAS.get_settable_quotas(context, project_id,
#                                                         user_id=user_id)
#        except exception.NotAuthorized:
#            raise webob.exc.HTTPForbidden()
#
#        for key, value in body['quota_set'].items():
#            if (key not in QUOTAS and
#                    key not in NON_QUOTA_KEYS):
#                bad_keys.append(key)
#                continue
#            if key == 'force' and extended_loaded:
#                # only check the force optional when the extended has
#                # been loaded
#                force_update = strutils.bool_from_string(value)
#            elif key not in NON_QUOTA_KEYS and value:
#                try:
#                    value = int(value)
#                except (ValueError, TypeError):
#                    msg = _("Quota '%(value)s' for %(key)s should be "
#                            "integer.") % {'value': value, 'key': key}
#                    LOG.warn(msg)
#                    raise webob.exc.HTTPBadRequest(explanation=msg)
#
#        LOG.debug(_("force update quotas: %s") % force_update)
#
#        if len(bad_keys) > 0:
#            msg = _("Bad key(s) %s in quota_set") % ",".join(bad_keys)
#            raise webob.exc.HTTPBadRequest(explanation=msg)
#
#        try:
#            quotas = self._get_quotas(context, id, user_id=user_id,
#                                      usages=True)
#        except exception.NotAuthorized:
#            raise webob.exc.HTTPForbidden()
#
#        for key, value in body['quota_set'].items():
#            if key in NON_QUOTA_KEYS or (not value and value != 0):
#                continue
#            # validate whether already used and reserved exceeds the new
#            # quota, this check will be ignored if admin want to force
#            # update
#            try:
#                value = int(value)
#            except (ValueError, TypeError):
#                msg = _("Quota '%(value)s' for %(key)s should be "
#                        "integer.") % {'value': value, 'key': key}
#                LOG.warn(msg)
#                raise webob.exc.HTTPBadRequest(explanation=msg)
#
#            if force_update is not True and value >= 0:
#                quota_value = quotas.get(key)
#                if quota_value and quota_value['limit'] >= 0:
#                    quota_used = (quota_value['in_use'] +
#                                  quota_value['reserved'])
#                    LOG.debug(_("Quota %(key)s used: %(quota_used)s, "
#                                "value: %(value)s."),
#                              {'key': key, 'quota_used': quota_used,
#                               'value': value})
#                    if quota_used > value:
#                        msg = (_("Quota value %(value)s for %(key)s are "
#                               "greater than already used and reserved "
#                               "%(quota_used)s") %
#                               {'value': value, 'key': key,
#                                'quota_used': quota_used})
#                        raise webob.exc.HTTPBadRequest(explanation=msg)
#
#            minimum = settable_quotas[key]['minimum']
#            maximum = settable_quotas[key]['maximum']
#            self._validate_quota_limit(value, minimum, maximum, force_update)
#            try:
#                db.quota_create(context, project_id, key, value,
#                                user_id=user_id)
#            except exception.QuotaExists:
#                db.quota_update(context, project_id, key, value,
#                                user_id=user_id)
#            except exception.AdminRequired:
#                raise webob.exc.HTTPForbidden()
#        return {'quota_set': self._get_quotas(context, id, user_id=user_id)}
#
#    @wsgi.serializers(xml=QuotaTemplate)
#    def defaults(self, req, id):
#        context = req.environ['manila.context']
#        authorize_show(context)
#        return self._format_quota_set(id, QUOTAS.get_defaults(context))
#
#    def delete(self, req, id):
#        if self.ext_mgr.is_loaded('os-extended-quotas'):
#            context = req.environ['manila.context']
#            authorize_delete(context)
#            params = urlparse.parse_qs(req.environ.get('QUERY_STRING', ''))
#            user_id = params.get('user_id', [None])[0]
#            if user_id and not self.ext_mgr.is_loaded('os-user-quotas'):
#                raise webob.exc.HTTPNotFound()
#            try:
#                sqlalchemy_api.authorize_project_context(context, id)
#                if user_id:
#                    QUOTAS.destroy_all_by_project_and_user(context,
#                                                           id, user_id)
#                else:
#                    QUOTAS.destroy_all_by_project(context, id)
#                return webob.Response(status_int=202)
#            except exception.NotAuthorized:
#                raise webob.exc.HTTPForbidden()
#        raise webob.exc.HTTPNotFound()


class Share_exports(extensions.ExtensionDescriptor):
    """Share exports management support"""

    name = "ShareExports"
    alias = "os-exports"
    namespace = "http://docs.openstack.org/compute/ext/exports/api/v1.1"
    updated = "2011-08-08T00:00:00+00:00"

    def get_resources(self):
        resources = []
        res = extensions.ResourceExtension('os-exports',
                                        ShareExportsController(self.ext_mgr),
                                        member_actions={'defaults': 'GET'})
        resources.append(res)

        return resources
