from snowflake_keypair_helper.api import (
    connect_env_keypair,
)

conn = connect_env_keypair(env_path="jasoncred.env")
with conn.cursor() as cursor:
    cursor.execute("select * from xorq_test.public.health_exp")
    results = cursor.fetchall()
    print(results)
