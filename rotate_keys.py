import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import xorq.api as xo



SF_USER = os.environ["SF_USER"]
SF_ACCOUNT = os.environ["SF_ACCOUNT"]
SF_PRIVATE_KEY = os.environ["SNOWFLAKE_PRIVATE_KEY_B64"]  # stored in GitHub secret


def load_private_key_from_github():
    key_bytes = base64.b64decode(SF_PRIVATE_KEY)
    return serialization.load_pem_private_key(key_bytes, password=None)


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, private_pem, public_pem


def connect_with_private_key(private_key_obj):
    pk_der = private_key_obj.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    return xo.snowflake.connect(
        user=SF_USER,
        account=SF_ACCOUNT,
        private_key=pk_der,
    )


def rotate_keys():
    # Load the existing key from GitHub Secrets
    current_key = load_private_key_from_github()

    conn = connect_with_private_key(current_key)

    # Generate new key pair
    new_key_obj, new_private_pem, new_public_pem = generate_rsa_keypair()

    print("🔑 Generated new RSA key pair")

    # Install as RSA_PUBLIC_KEY_2 (standby)
    conn.sql(
        f"ALTER USER {SF_USER} SET RSA_PUBLIC_KEY_2='{new_public_pem.decode()}'"
    )
    print("➡️ Installed new key into RSA_PUBLIC_KEY_2")

    # Promote standby to primary
    conn.sql(
        f"ALTER USER {SF_USER} SET RSA_PUBLIC_KEY='{new_public_pem.decode()}'"
    )
    print("➡️ Promoted new key to RSA_PUBLIC_KEY")

    # Clear old secondary key
    conn.sql(
        f"ALTER USER {SF_USER} UNSET RSA_PUBLIC_KEY_2"
    )
    print("➡️ Cleared RSA_PUBLIC_KEY_2")

    conn.sql()

    return new_private_pem


def update_github_secret(new_private_key_pem):
    """
    Writes the new key to a file that GitHub Actions will read and update as a secret.
    """
    with open("new_key_b64.txt", "w") as f:
        f.write(base64.b64encode(new_private_key_pem).decode())


if __name__ == "__main__":
    new_private_key = rotate_keys()
    update_github_secret(new_private_key)
    print("✅ Rotation complete; new key saved to file for GitHub Actions secret update")
