# Copyright (c) 2010 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
The swift3 middleware will emulate the S3 REST api on top of swift.

The following opperations are currently supported:

    * GET Service
    * DELETE Bucket
    * GET Bucket (List Objects)
    * PUT Bucket
    * DELETE Object
    * Delete Multiple Objects
    * GET Object
    * HEAD Object
    * PUT Object
    * PUT Object (Copy)

To add this middleware to your configuration, add the swift3 middleware
in front of the auth middleware, and before any other middleware that
look at swift requests (like rate limiting).

To set up your client, the access key will be the concatenation of the
account and user strings that should look like test:tester, and the
secret access key is the account password.  The host should also point
to the swift storage hostname.  It also will have to use the old style
calling format, and not the hostname based container format.

An example client using the python boto library might look like the
following for an SAIO setup::

    from boto.s3.connection import S3Connection
    connection = S3Connection(
        aws_access_key_id='test:tester',
        aws_secret_access_key='testing',
        port=8080,
        host='127.0.0.1',
        is_secure=False,
        calling_format=boto.s3.connection.OrdinaryCallingFormat())
"""

from urllib import unquote, quote
import base64
import urlparse

import email.utils
import datetime

from swift3.s3controllers import ServiceController, BucketController, ObjectController
from swift.common.utils import split_path
from swift.common.utils import get_logger
from swift.common.swob import Request
from swift.common.http import HTTP_OK, HTTP_CREATED, HTTP_ACCEPTED, \
    HTTP_NO_CONTENT, HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED, HTTP_FORBIDDEN, \
    HTTP_NOT_FOUND, HTTP_CONFLICT, HTTP_UNPROCESSABLE_ENTITY, is_success, \
    HTTP_NOT_IMPLEMENTED, HTTP_LENGTH_REQUIRED, HTTP_SERVICE_UNAVAILABLE
from swift3.s3controllers.base import BaseController

# TODO better implement
_in = BaseController()
get_err_response = lambda arg: _in.get_err_response(arg)


def canonical_string(req):
    """
    Canonicalize a request to a token that can be signed.
    """
    amz_headers = {}

    buf = "%s\n%s\n%s\n" % (req.method, req.headers.get('Content-MD5', ''),
                            req.headers.get('Content-Type') or '')

    for amz_header in sorted((key.lower() for key in req.headers
                              if key.lower().startswith('x-amz-'))):
        amz_headers[amz_header] = req.headers[amz_header]

    if 'x-amz-date' in amz_headers:
        buf += "\n"
    elif 'Date' in req.headers:
        buf += "%s\n" % req.headers['Date']

    for k in sorted(key.lower() for key in amz_headers):
        buf += "%s:%s\n" % (k, amz_headers[k])

    # RAW_PATH_INFO is enabled in later version than eventlet 0.9.17.
    # When using older version, swift3 uses req.path of swob instead
    # of it.
    path = req.environ.get('RAW_PATH_INFO', req.path)
    if req.query_string:
        path += '?' + req.query_string
    if '?' in path:
        path, args = path.split('?', 1)
        qstr = ''
        qdict = dict(urlparse.parse_qsl(args, keep_blank_values=True))
        #
        # List of  sub-resources that must be maintained as part of the HMAC
        # signature string.
        #
        keywords = sorted(['acl', 'delete', 'lifecycle', 'location', 'logging',
            'notification', 'partNumber', 'policy', 'requestPayment',
            'torrent', 'uploads', 'uploadId', 'versionId', 'versioning',
            'versions ', 'website', 'cors', 'tagging'])
        for key in qdict:
            if key in keywords:
                newstr = key
                if qdict[key]:
                    newstr = newstr + '=%s' % qdict[key]

                if qstr == '':
                    qstr = newstr
                else:
                    qstr = qstr + '&%s' % newstr

        if qstr != '':
            return "%s%s?%s" % (buf, path, qstr)

    return buf + path


class Swift3Middleware(object):
    """Swift3 S3 compatibility midleware"""
    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        self.conf = conf
        self.logger = get_logger(self.conf, log_route='swift3')

    def get_controller(self, env, path):
        # TODO support container.xx.xx.xx
        container, obj = split_path(path, 0, 2, True)
        d = dict(container_name=container, object_name=obj)

        if 'QUERY_STRING' in env:
            args = dict(urlparse.parse_qsl(env['QUERY_STRING'], 1))
        else:
            args = {}

        if container and obj:
            if env['REQUEST_METHOD'] == 'POST':
                if 'uploads' or 'uploadId' in args:
                    return BucketController, d
            return ObjectController, d
        elif container:
            return BucketController, d

        return ServiceController, d

    def __call__(self, env, start_response):
        try:
            return self.handle_request(env, start_response)
        except Exception, e:
            self.logger.exception(e)
        return get_err_response('ServiceUnavailable')(env, start_response)

    def handle_request(self, env, start_response):
        req = Request(env)
        self.logger.debug('Calling Swift3 Middleware')
        #self.logger.debug(req.__dict__)

        if 'AWSAccessKeyId' in req.params:
            try:
                req.headers['Date'] = req.params['Expires']
                req.headers['Authorization'] = \
                    'AWS %(AWSAccessKeyId)s:%(Signature)s' % req.params
            except KeyError:
                return get_err_response('InvalidArgument')(env, start_response)

        if 'Authorization' not in req.headers:
            return self.app(env, start_response)

        try:
            keyword, info = req.headers['Authorization'].split(' ')
        except:
            return get_err_response('AccessDenied')(env, start_response)

        if keyword != 'AWS':
            return get_err_response('AccessDenied')(env, start_response)

        try:
            account, signature = info.split(':', 1)
        except:
            return get_err_response('InvalidArgument')(env, start_response)

        try:
            controller, path_parts = self.get_controller(env, req.path)
        except ValueError:
            return get_err_response('InvalidURI')(env, start_response)

        #print controller, req.method
        if 'Date' in req.headers:
            date = email.utils.parsedate(req.headers['Date'])
            if date is None and 'Expires' in req.params:
                d = email.utils.formatdate(float(req.params['Expires']))
                date = email.utils.parsedate(d)

            if date is None:
                return get_err_response('AccessDenied')(env, start_response)

            d1 = datetime.datetime(*date[0:6])
            d2 = datetime.datetime.utcnow()
            epoch = datetime.datetime(1970, 1, 1, 0, 0, 0, 0)

            if d1 < epoch:
                return get_err_response('AccessDenied')(env, start_response)

            delta = datetime.timedelta(seconds=60 * 5)
            if d1 - d2 > delta or d2 - d1 > delta:
                return get_err_response('RequestTimeTooSkewed')(env,
                                                                start_response)

        token = base64.urlsafe_b64encode(canonical_string(req))

        controller = controller(env, self.app, account, token, conf=self.conf,
                                **path_parts)

        if hasattr(controller, req.method):
            res = getattr(controller, req.method)(env, start_response)
        else:
            return get_err_response('InvalidURI')(env, start_response)

        return res(env, start_response)


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""
    conf = global_conf.copy()
    conf.update(local_conf)

    def swift3_filter(app):
        return Swift3Middleware(app, conf)

    return swift3_filter
