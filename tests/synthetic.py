"""The only personal-looking values allowed anywhere in this repository.

Every value here is synthetic. `test_repo_clean.py` scans the whole repository with the plugin's own
detectors and fails on any value that is not listed in SYNTHETIC.

How the values were chosen:
- e-mail: reserved names only (RFC 2606 and RFC 6761: example.*, .test, .invalid);
- phone: UK numbers from the Ofcom drama range (+44 7700 900xxx), US numbers from the 555-0100..0199
  range reserved for fiction, Polish numbers with zero-filled subscriber parts (Poland has no official
  fiction range, so these are chosen to be unlikely, not guaranteed unassigned);
- PESEL: checksum-valid numbers with birth dates in the 2090s, so they cannot belong to anyone alive;
- IBAN: bank code 00000000 (not assigned in PL or DE) and the ECBS documentation example "WEST" bank;
- cards: public test numbers published by card networks and payment processors for testing.
"""

EMAILS = [
    "alice@mail.test",
    "bob.builder@shop.invalid",
    "carol+news@corp.test",
    "user@example.com",
    "info@sub.example.org",
]
PHONES = [
    "+44 7700 900123",
    "+447700900456",
    "+1 (202) 555-0123",
    "+1 202 555 0199",
    "+48 22 000 00 01",
    "22 000 00 02",
    "(22) 000 00 03",
    "500 000 004",
    "500-000-005",
    "500000006",
]
PESELS = ["90210100005", "95323100001", "96222900002", "90210100012"]
IBANS = [
    "PL74000000000000000000000001",
    "PL74 0000 0000 0000 0000 0000 0001",
    "74 0000 0000 0000 0000 0000 0001",
    "DE09000000000000000001",
    "GB82WEST12345698765432",
    "GB82 WEST 1234 5698 7654 32",
]
CARDS = [
    "4111111111111111",
    "4111 1111 1111 1111",
    "5555555555554444",
    "5555-5555-5555-4444",
    "378282246310005",
    "4012888888881881",
]
# Addresses that the default configuration allows (automation senders, git SSH user, placeholders).
ALLOWED_EMAILS = [
    "x@host.localhost",
    "git@github.com",
    "noreply@vendor.invalid",
    "12345+someone@users.noreply.github.com",
]
PHRASES = ["Acme Secret Project"]

SYNTHETIC = EMAILS + ALLOWED_EMAILS + PHONES + PESELS + IBANS + CARDS + PHRASES
