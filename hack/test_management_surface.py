"""I07 removes alternative public management authorization and CLI entrypoints."""
import re
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
class ManagementSurface(unittest.TestCase):
    def test_no_password_candidate_management(self):
        for name in ('operations.rs', 'federation.rs'):
            source = (ROOT / 'crates/identity-postgres/src' / name).read_text()
            for signature in re.findall(r'pub(?:\([^)]*\))? async fn (\w+)\s*\((.*?)\)\s*->', source, re.S):
                self.assertNotIn('actor: AuthenticationCandidate', signature[1], signature[0])
    def test_only_maintenance_cli(self):
        source = (ROOT / 'app/identity-admin/src/main.rs').read_text()
        self.assertNotIn('Command::Idp', source)
        self.assertNotIn('AuthorityProfile::Runtime', source)
        self.assertIn('initialize', source)
        self.assertIn('recover', source)
    def test_no_generic_public_account_change(self):
        source = (ROOT / 'crates/identity-postgres/src/operations.rs').read_text()
        self.assertNotRegex(source, r'pub async fn change_account\(')
if __name__ == '__main__': unittest.main()
