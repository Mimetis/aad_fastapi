import base64
import binascii
from typing import Dict

from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
from azure.keyvault.secrets import SecretClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12


class AadVault:
    """Azure Key Vault client"""

    def __init__(self, vault_url: str):
        self.vault_url = vault_url

    def get_certificate(self, vault_certificate_key: str):
        credential = DefaultAzureCredential()

        certificate_client = CertificateClient(self.vault_url, credential)
        secret_client = SecretClient(self.vault_url, credential)

        # Get the certificate secret that contains the private key
        certificate_secret = secret_client.get_secret(name=vault_certificate_key)

        # Get the certificate that contains the encoded thumbprint
        certificate = certificate_client.get_certificate(
            certificate_name=vault_certificate_key
        )

        # Get the hexadecimal thumbprint from X509 binary thumbprint value
        thumbprint = binascii.hexlify(certificate.properties.x509_thumbprint)

        certificate = {
            "private_key": certificate_secret.value,
            "thumbprint": thumbprint,
            "x_type": certificate_secret.properties._content_type,
        }
        return certificate

    def get_secret(self, vault_secret_key: str):
        credential = DefaultAzureCredential()
        secret_client = SecretClient(self.vault_url, credential)

        # Get the certificate secret that contains the private key
        secret = secret_client.get_secret(name=vault_secret_key)

        return secret.value

    @staticmethod
    def get_msal_client_credential(certificate: Dict):
        # get certificate type
        thumbprint = certificate["thumbprint"]
        private_key = certificate["private_key"]
        content_type = certificate.get("x_type", "x-pem-file")

        if "x-pem-file" in content_type:
            # Create the credential
            client_credential = {
                "thumbprint": thumbprint,
                "private_key": serialization.load_pem_private_key(
                    private_key.encode(), password=None
                ),
            }
        else:
            # Get the bytes from the base64 value
            cert_bytes = base64.b64decode(private_key)

            (
                private_key,
                public_certificate,
                additional_certificates,
            ) = pkcs12.load_key_and_certificates(data=cert_bytes, password=None)

            client_credential = {
                "thumbprint": thumbprint,
                "private_key": private_key,
            }

        return client_credential
