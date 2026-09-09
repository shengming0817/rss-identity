"""I07 removes alternative public management authorization and CLI entrypoints."""
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
class ManagementSurface(unittest.TestCase):
    def test_only_maintenance_cli(self):
        source = (ROOT / 'app/identity/src/bin/admin.rs').read_text()
        self.assertNotIn('Command::Idp', source)
        self.assertNotIn('AuthorityProfile::Runtime', source)
        self.assertIn('initialize', source)
        self.assertIn('recover', source)
        library = (ROOT / 'app/identity/src/lib.rs').read_text()
        self.assertNotIn('IdpInputError', library)
        self.assertNotIn('expected member, admin or emergency', library)
    def test_no_generic_public_account_change(self):
        source = (ROOT / 'crates/identity-postgres/src/operations.rs').read_text()
        self.assertNotRegex(source, r'pub async fn change_account\(')
if __name__ == '__main__': unittest.main()
