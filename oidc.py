# Example of OIDC
# This file contains the Azure OpenID Connect helper class that is needed
# to verify the JWT token received in the protected routes
import logging
import threading
from typing import Any, Dict, List

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import load_pem_x509_certificate

from app.core.errors import ErrorInvalidJWT, FailureAzureOIDC
from app.utils.date import get_current_date_since_epoch_in_seconds, get_future_date_since_epoch_in_seconds

logger = logging.getLogger(__name__)


def http_get_json(url: str) -> Dict[str, Any]:
    resp = requests.get(url, timeout=5)
    if not resp.ok:
        logger.error("Received %d response code from %s", resp.status_code, url)
        raise FailureAzureOIDC(detailed_message=f"Received {resp.status_code} response code from {url}")
    try:
        return resp.json()
    except (ValueError, TypeError):
        logger.error("Received malformed response from %s", url)
        raise FailureAzureOIDC(detailed_message=f"Received malformed response from {url}") from None


class AzureKeystore:
    """
    AzureKeystore class holds the Azure AD keys that are needed to verify the JWT token
    """

    def __init__(self, jwks_uri: str, algorithms: List[str], issuer: str, fetch_keys: bool = True) -> None:
        self._keys: Dict[str, str] = {}
        # 86400 = 1 day
        self._expires_at: int = get_future_date_since_epoch_in_seconds(delta=86400)
        self.algorithms: List[str] = algorithms
        self.issuer: str = issuer
        if fetch_keys:
            self._fetch_keys(jwks_uri)

    def _fetch_keys(self, jwks_uri: str) -> None:
        resp = http_get_json(jwks_uri)
        for pubk in resp.get("keys"):
            if pubk.get("use") != "sig":
                continue
            kid = pubk.get("kid")
            x5c = pubk.get("x5c")[0]
            pem = f"-----BEGIN CERTIFICATE-----\n{x5c}\n-----END CERTIFICATE-----\n"
            key = load_pem_x509_certificate(pem.encode(), default_backend()).public_key()
            self._keys[kid] = key.public_bytes(Encoding.PEM, PublicFormat.PKCS1).decode("utf-8")

        if len(self._keys) < 1:
            raise FailureAzureOIDC(detailed_message="There are no usable keys in keystore")

    def is_expired(self) -> bool:
        """
        Checks if the keystore is more than 1 day old
        """
        return get_current_date_since_epoch_in_seconds() > self._expires_at

    def find_key(self, kid: str) -> str:
        """
        finds the key via the key identifier
        """
        if kid not in self._keys:
            raise ErrorInvalidJWT(detailed_message=f"Cannot find key with id {kid}")
        return self._keys[kid]


class AzureOpenIdConnect:
    """
    AzureOpenIdConnect verifies the token using the Azure AD OpenID configuration
    retrieved from the server; this class also keeps a copy of the configuration
    and reloads it every day

    Details related to the refresh strategy:

    For security purposes, the Microsoft identity platform’s signing key rolls on
    a periodic basis and, in the case of an emergency, could be rolled over
    immediately. There is no set or guaranteed time between these key rolls - any
    application that integrates with the Microsoft identity platform should be
    prepared to handle a key rollover event no matter how frequently it may occur.
    If the application doesn't handle sudden refreshes, and attempts to use an
    expired key to verify the signature on a token, your application will incorrectly
    reject the token. Checking every 24 hours for updates is a best practice, with
    throttled (once every five minutes at most) immediate refreshes of the key
    document if a token is encountered that doesn't validate with the keys in
    your application's cache.

    Source:
    https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-signing-key-rollover#overview-of-signing-keys-in-the-microsoft-identity-platform
    """

    def __init__(self, openid_url: str) -> None:
        self._openid_url: str = openid_url
        self._keystore: AzureKeystore = None
        self._refresh_lock = threading.Lock()

    def _refresh(self) -> None:
        with self._refresh_lock:
            if self._keystore is not None and not self._keystore.is_expired():
                return

            config = http_get_json(self._openid_url)
            keys_uri = config.get("jwks_uri")
            algorithms = config.get("id_token_signing_alg_values_supported")
            issuer = config.get("issuer")
            self._keystore = AzureKeystore(keys_uri, algorithms, issuer)

    def get_keystore(self) -> AzureKeystore:
        self._refresh()
        return self._keystore
