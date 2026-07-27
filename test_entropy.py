import unittest

from secretscope.entropy import extract_candidate_tokens, is_high_entropy, shannon_entropy


class TestShannonEntropy(unittest.TestCase):
    def test_empty_string_has_zero_entropy(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_repeated_character_has_zero_entropy(self):
        self.assertEqual(shannon_entropy("aaaaaaaaaa"), 0.0)

    def test_random_looking_token_has_high_entropy(self):
        token = "aK9x2LpQz7mN4vWbR8tYc1sJ"
        self.assertGreater(shannon_entropy(token), 3.5)

    def test_english_word_has_lower_entropy_than_random_token(self):
        word = "helloworldhelloworld"
        token = "aK9x2LpQz7mN4vWbR8tYc1sJ"
        self.assertLess(shannon_entropy(word), shannon_entropy(token))


class TestIsHighEntropy(unittest.TestCase):
    def test_low_entropy_token_is_not_flagged(self):
        self.assertFalse(is_high_entropy("aaaaaaaaaaaaaaaa", threshold=4.0))

    def test_high_entropy_token_is_flagged(self):
        self.assertTrue(is_high_entropy("aK9x2LpQz7mN4vWbR8tYc1sJ", threshold=3.5))

    def test_custom_threshold_respected(self):
        token = "abcdefghijklmnop"  # moderate entropy, sequential chars
        self.assertFalse(is_high_entropy(token, threshold=10.0))


class TestExtractCandidateTokens(unittest.TestCase):
    def test_extracts_long_tokens_only(self):
        line = "short = 'hi' and long_token = 'aK9x2LpQz7mN4vWbR8tYc1sJ'"
        tokens = extract_candidate_tokens(line)
        self.assertIn("aK9x2LpQz7mN4vWbR8tYc1sJ", tokens)
        self.assertNotIn("hi", tokens)

    def test_no_tokens_in_plain_sentence(self):
        line = "this is just a normal comment with no secrets"
        tokens = extract_candidate_tokens(line)
        # every word here is shorter than MIN_TOKEN_LENGTH
        self.assertEqual(tokens, [])


if __name__ == "__main__":
    unittest.main()
