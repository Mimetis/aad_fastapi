from aad_fastapi.aad_vault import AadVault


def test_get_msal_client_credential_when_x_type_is_x_pem_file():
    vault = AadVault("https://test.vault.azure.net")

    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization

    rsa_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    private_key = rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    mock_certificate = {
        "thumbprint": "test_thumbprint",
        "private_key": private_key,
        "x_type": "x-pem-file",
    }

    client_credentials = vault.get_msal_client_credential(mock_certificate)

    assert client_credentials["thumbprint"] == "test_thumbprint"
    key = client_credentials["private_key"]
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 2048
    assert key.public_key().key_size == 2048
    assert key.public_key().public_numbers().e == 65537
