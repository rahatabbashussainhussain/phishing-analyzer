"""
Unit tests for phishing_checker.py

Run with:
    python -m unittest test_phishing_checker.py
"""

import unittest

from phishing_checker import analyze_text, analyze_url, levenshtein_distance


class TestLevenshteinDistance(unittest.TestCase):
    def test_identical_strings(self):
        self.assertEqual(levenshtein_distance("paypal", "paypal"), 0)

    def test_one_char_difference(self):
        self.assertEqual(levenshtein_distance("paypal", "paypa1"), 1)

    def test_completely_different(self):
        self.assertGreater(levenshtein_distance("paypal", "xyz"), 3)


class TestAnalyzeUrl(unittest.TestCase):
    def test_legitimate_https_url_is_low_risk(self):
        result = analyze_url("https://www.google.com")
        self.assertEqual(result["risk_level"], "LOW")

    def test_ip_address_url_is_flagged(self):
        result = analyze_url("http://192.168.1.55/login")
        reasons_text = " ".join(result["reasons"])
        self.assertIn("IP address", reasons_text)

    def test_at_symbol_is_flagged(self):
        result = analyze_url("http://google.com@malicious-site.tk/login")
        reasons_text = " ".join(result["reasons"])
        self.assertIn("@", reasons_text)

    def test_typosquat_is_flagged_high_risk(self):
        result = analyze_url("http://paypa1-secure-login.tk/verify-account")
        self.assertEqual(result["risk_level"], "HIGH")
        reasons_text = " ".join(result["reasons"])
        self.assertIn("paypal", reasons_text)

    def test_url_shortener_is_flagged(self):
        result = analyze_url("https://bit.ly/3xample")
        reasons_text = " ".join(result["reasons"])
        self.assertIn("shortener", reasons_text)

    def test_legitimate_subdomain_not_flagged_as_typosquat(self):
        result = analyze_url("https://accounts.google.com/signin")
        reasons_text = " ".join(result["reasons"])
        self.assertNotIn("typosquat", reasons_text)


class TestAnalyzeText(unittest.TestCase):
    def test_finds_urls_in_text(self):
        text = "Please check this link: https://example.com and this one http://test.tk"
        result = analyze_text(text)
        self.assertEqual(result["url_count"], 2)

    def test_detects_urgency_language(self):
        text = "URGENT: your account will be suspended. Act now to avoid losing access."
        result = analyze_text(text)
        self.assertTrue(len(result["language_flags"]) > 0)

    def test_no_urls_found_returns_empty_list(self):
        text = "This message has no links in it at all."
        result = analyze_text(text)
        self.assertEqual(result["url_count"], 0)
        self.assertEqual(result["urls"], [])


if __name__ == "__main__":
    unittest.main()
