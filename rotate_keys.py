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
        role="ACCOUNTADMIN"
    )


def pem_to_snowflake_key(pem_bytes):
    pem_str = pem_bytes.decode()
    lines = pem_str.replace("-----BEGIN PUBLIC KEY-----", "") \
                   .replace("-----END PUBLIC KEY-----", "") \
                   .replace("\n", "")
    return lines


def rotate_keys():
    """
    Rotate the Snowflake key pair for the user using Xorq.
    Generates a new RSA key pair, installs the public key as standby,
    promotes it to primary, and removes the old secondary key.
    Returns the new private key in PEM bytes.
    """

    def pem_to_snowflake_key(pem_bytes):
        """
        Convert a PEM-formatted public key to the Snowflake-compatible
        single-line base64 format.
        """
        pem_str = pem_bytes.decode()
        return pem_str.replace("-----BEGIN PUBLIC KEY-----", "") \
                      .replace("-----END PUBLIC KEY-----", "") \
                      .replace("\n", "") \
                      .strip()  # Added strip() to remove any whitespace

    # Load the existing private key from GitHub secret
    current_key = load_private_key_from_github()
    conn = connect_with_private_key(current_key)
    print("get current role")
    print(conn.raw_sql(f"SELECT CURRENT_ROLE()").fetchone())

    # Generate a new RSA key pair
    new_key_obj, new_private_pem, new_public_pem = generate_rsa_keypair()
    sf_public_key = pem_to_snowflake_key(new_public_pem)
    print("🔑 Generated new RSA key pair")

    # Install as standby public key (RSA_PUBLIC_KEY_2)
    print(f"Setting RSA_PUBLIC_KEY_2 (length: {len(sf_public_key)} chars)")
    conn.raw_sql(f"ALTER USER {SF_USER} SET RSA_PUBLIC_KEY_2='{sf_public_key}'").fetchone()
    print("➡️ Installed new key into RSA_PUBLIC_KEY_2")

    # Promote the standby key to primary (RSA_PUBLIC_KEY)
    conn.raw_sql(f"ALTER USER {SF_USER} SET RSA_PUBLIC_KEY='{sf_public_key}'").fetchone()
    print("➡️ Promoted new key to RSA_PUBLIC_KEY")

    # Clear the old secondary key
    conn.raw_sql(f"ALTER USER {SF_USER} UNSET RSA_PUBLIC_KEY_2").fetchone()
    print("➡️ Cleared RSA_PUBLIC_KEY_2")

    print("Selecting data from the table we created")
    conn.raw_sql("USE WAREHOUSE COMPUTE_WH").fetchone()
    fetch_all_records_from_table = conn.raw_sql("SELECT * FROM XORQ_TEST.PUBLIC.HEALTH_EXP LIMIT 10").fetchall()
    print(fetch_all_records_from_table)

    # Return the new private key in PEM bytes
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
    
