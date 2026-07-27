import unittest

from secretscope.patterns import SECRET_PATTERNS


class TestSecretPatterns(unittest.TestCase):
    def test_aws_access_key_matches(self):
        line = 'aws_key = "AKIAABCDEFGHIJKLMNOP"'
        self.assertTrue(SECRET_PATTERNS["AWS Access Key ID"].search(line))

    def test_github_pat_matches(self):
        line = 'token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"'
        self.assertTrue(SECRET_PATTERNS["GitHub Personal Access Token"].search(line))

    def test_anthropic_key_matches(self):
        line = 'ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890'
        self.assertTrue(SECRET_PATTERNS["Anthropic API Key"].search(line))

    def test_groq_key_matches(self):
        line = 'GROQ_API_KEY = "gsk_abcdefghijklmnopqrstuvwxyz1234567890"'
        self.assertTrue(SECRET_PATTERNS["Groq API Key"].search(line))

    def test_private_key_block_matches(self):
        line = "-----BEGIN RSA PRIVATE KEY-----"
        self.assertTrue(SECRET_PATTERNS["Private Key Block"].search(line))

    def test_db_connection_string_matches(self):
        line = "DATABASE_URL=postgresql://admin:sup3rSecret@db.example.com:5432/prod"
        self.assertTrue(SECRET_PATTERNS["Database Connection String"].search(line))

    def test_plain_code_does_not_match_any_pattern(self):
        line = "def add(a, b):\n    return a + b"
        for name, pattern in SECRET_PATTERNS.items():
            self.assertFalse(pattern.search(line), f"False positive on rule: {name}")

    def test_generic_assignment_matches(self):
        line = 'password: "SuperSecretValue123"'
        self.assertTrue(SECRET_PATTERNS["Generic API Key/Secret Assignment"].search(line))


if __name__ == "__main__":
    unittest.main()
