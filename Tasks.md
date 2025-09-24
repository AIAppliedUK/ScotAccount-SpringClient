1. Update the codebase to seperate the authentication and verification flows.
   1.1 Update the application to only perform an authentication step.
   1.2 Once the authentication step is complete the portal page (index.html) should present check boxes for the gpg45.medium, scotaccount.email and scotaccount address scopes.
   1.3 The portal page should display a button below thecheckboxes to then allow the user to request the additional attributes such as email, address or gpg45medium verification.
2. Fix logout to ensure logout url is called on scotaccount service once local logout session is complete.
3. Handle user declining to share email, address or verification status
4. Properly Manage session times out
5. Confirm what happens when user verification is required.
   4.1 Verfiication that completes within 15 minutes
   4.2 Verification that takes longer than 15 minutes

## Completed Tasks

### JWK Generator Command Line Utility (2024-12-19)

- ✅ Created JWKGenerator CLI utility class with main method
- ✅ Implemented RSA key generation functionality (2048, 3072, 4096 bits)
- ✅ Implemented Elliptic Curve key generation functionality (P-256, P-384, P-521)
- ✅ Added comprehensive command line argument parsing
- ✅ Created extensive unit tests covering all functionality
- ✅ Added support for key usage (signature/encryption) and public-only output
- ✅ Follows exact patterns from Nimbus JOSE+JWT documentation

**Usage Examples:**

```bash
# Generate 2048-bit RSA key for signatures
java JWKGenerator --type RSA --size 2048 --use sig

# Generate P-256 EC key for signatures
java JWKGenerator --type EC --curve P-256 --use sig

# Generate 4096-bit RSA key for encryption (public only)
java JWKGenerator --type RSA --size 4096 --use enc --public-only
```
