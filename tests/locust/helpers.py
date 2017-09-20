from locust.clients import LocustResponse, HttpSession

import requests
from requests import Request
from requests.exceptions import (
    RequestException,
    MissingSchema,
    InvalidSchema,
    InvalidURL
)

from sigauth.utils import RequestSigner
from tests import settings


class AuthenticatedClient(HttpSession):
    def _send_request_safe_mode(self, method, url, **kwargs):
        kwargs.pop('allow_redirects', None)
        try:
            request = requests.Request(method=method, url=url, **kwargs)
            signed_request = self.sign_request(
                secret=settings.API_SIGNATURE_SECRET,
                request=request.prepare(),
            )
            return requests.Session().send(signed_request)
        except (MissingSchema, InvalidSchema, InvalidURL):
            raise
        except RequestException as e:
            r = LocustResponse()
            r.error = e
            r.status_code = 0  # with this status_code, content returns None
            r.request = Request(method, url).prepare()
            return r

    def sign_request(self, secret, request):
        signer = RequestSigner(secret=secret)
        headers = signer.get_signature_headers(
            url=request.path_url,
            body=request.body,
            method=request.method,
            content_type=request.headers.get('Content-Type')
        )
        return request.headers.update(headers)


class AuthedClientMixin(object):
    def __init__(self):
        super(AuthedClientMixin, self).__init__()
        self.client = AuthenticatedClient(base_url=self.host)
