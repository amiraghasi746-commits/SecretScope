"""
DELIBERATELY INSECURE FILE - for demo/testing purposes only.

This file contains fake, non-functional secrets used to demonstrate
SecretScope's detection capabilities. Do not use real secrets here.
"""

AWS_ACCESS_KEY_ID = "AKIAFAKEKEY1234EXAMP"
AWS_SECRET_ACCESS_KEY = "wJalrFAKEsecretKeyExampleNotReal12345678"

GITHUB_TOKEN = "ghp_FakeToken1234567890abcdefghijklmnoPQRS"

ANTHROPIC_API_KEY = "sk-ant-api03-FAKEKEYFAKEKEYFAKEKEYFAKEKEY1234567890"

DATABASE_URL = "postgresql://admin:fakePassword123@db.internal.example.com:5432/prod"

# A private key block (fake) to trigger the "Private Key Block" rule
FAKE_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
FAKEKEYDATAFAKEKEYDATAFAKEKEYDATAFAKEKEYDATA
-----END RSA PRIVATE KEY-----"""

# A generic high-entropy string with no recognizable signature
random_looking_token = "aK9x2LpQz7mN4vWbR8tYc1sJ9Zq3Rt6Wp0Xy"
