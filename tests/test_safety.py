import unittest
from unittest.mock import patch

from dast_harness.safety import TargetNotAuthorizedError, authorize_target


class AuthorizeTargetTests(unittest.TestCase):
    def test_allows_literal_ipv4_loopback(self) -> None:
        authorized = authorize_target("http://127.0.0.1:8080")
        self.assertEqual(authorized.host, "127.0.0.1")

    def test_allows_literal_ipv6_loopback(self) -> None:
        authorized = authorize_target("http://[::1]:8080")
        self.assertEqual(authorized.host, "::1")

    @patch(
        "dast_harness.safety._resolve_ips",
        return_value=["127.0.0.1", "::1"],
    )
    def test_allows_localhost_when_all_addresses_are_loopback(self, _resolve) -> None:
        authorized = authorize_target("http://localhost:3000")
        self.assertEqual(authorized.host, "localhost")

    def test_rejects_private_network_by_default(self) -> None:
        with self.assertRaises(TargetNotAuthorizedError):
            authorize_target("http://192.168.1.10")

    def test_rejects_link_local_by_default(self) -> None:
        with self.assertRaises(TargetNotAuthorizedError):
            authorize_target("http://169.254.169.254/latest/meta-data/")

    def test_rejects_arbitrary_hostname_by_default(self) -> None:
        with self.assertRaises(TargetNotAuthorizedError):
            authorize_target("https://example.com")

    def test_allowlist_is_case_insensitive(self) -> None:
        authorized = authorize_target(
            "https://STAGING.example.com", {"staging.EXAMPLE.com"}
        )
        self.assertEqual(authorized.host, "staging.example.com")

    def test_rejects_invalid_scheme(self) -> None:
        with self.assertRaises(TargetNotAuthorizedError):
            authorize_target("file:///etc/passwd")

    def test_rejects_invalid_port(self) -> None:
        with self.assertRaises(TargetNotAuthorizedError):
            authorize_target("http://127.0.0.1:not-a-port")


if __name__ == "__main__":
    unittest.main()
