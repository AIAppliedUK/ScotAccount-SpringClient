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
