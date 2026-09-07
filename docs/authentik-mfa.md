  ### How Authentik Handles This Conceptually

  1. Authenticator Setup Stages: Authentik includes built-in stages that handle registration:
      • default-authenticator-webauthn-setup (Hardware security keys like YubiKeys, Passkeys, FIDO2)
      • default-authenticator-totp-setup (Google Authenticator, Microsoft Authenticator, 1Password, Yubico Authenticator)
  2. Authenticator Validation Stage (default-authentication-mfa-validation): This is the gatekeeper. By setting its "Not configured action" to Configure,
  Authentik detects when a user does not have an MFA device and forces them to register one before proceeding.
  3. Configuration Stages Order: Placing WebAuthn ahead of TOTP makes YubiKey the default/recommended option presented to the user.
  ──────
  ### Step-by-Step Changes in the Authentik Admin Interface

  Log into your Authentik admin console at https://auth.<your-domain>/if/admin/#/flow/stages as akadmin or your administrative user.
  ──────
  ### Step 1: Configure the Authenticator Validation Stage

  1. In the sidebar, expand Flows and Stages and click Stages.
  2. Locate and edit the stage named default-authentication-mfa-validation (Stage Type: Authenticator Validation Stage).
  3. Configure the following settings:
      • Device classes: Check WebAuthn authenticators and TOTP authenticators (uncheck Static tokens or Duo unless you use them).
      • Not configured action: Change from Skip to Force the user to configure an authenticator (configure).
      • Configuration stages: In the multi-select box, select both:
          1. default-authenticator-webauthn-setup
          2. default-authenticator-totp-setup
          (Tip: Holding Ctrl / Cmd allows selecting multiple. The order listed determines which is presented first).
      • WebAuthn User Verification: Set to preferred (or discouraged if you want simple touch-to-auth without requiring a PIN on the YubiKey).
  4. Click Update.
  ──────
  ### Step 2: Ensure MFA is Enforced on Login (default-authentication-flow)

  1. In the sidebar, go to Flows and Stages > Flows.
  2. Click on default-authentication-flow and go to the Stage Bindings tab.
  3. Verify the sequence:
   Order                                              | Stage                                              | Purpose
  ----------------------------------------------------|----------------------------------------------------|----------------------------------------------------
   10                                                 | default-authentication-identification              | Prompts for username/email
   20                                                 | default-authentication-password                    | Validates primary password
   30                                                 | default-authentication-mfa-validation              | Enforces MFA / Enrolls if missing
   100                                                | default-authentication-login                       | Logs user into the session


  │ Note
  │ If default-authentication-mfa-validation is already bound at order 30, Step 1 automatically takes effect for logins. Existing users without MFA will be
  │ forced to register a YubiKey or TOTP app upon their next password entry.
  ──────
  ### Step 3: Enforce MFA During Signup / Enrollment (default-enrollment-flow)

  By default, enrollment flows create the user and immediately log them in via default-enrollment-login, which would bypass the authentication flow unless
  intercepted:

  1. In Flows and Stages > Flows, click on your enrollment flow (typically default-enrollment-flow).
  2. Go to the Stage Bindings tab. The default stages are usually:
      • default-enrollment-prompt (Order 10: username, email, password)
      • default-enrollment-user-write (Order 20: writes user record to PostgreSQL)
      • default-enrollment-login (Order 100: logs user in)
  3. Click Bind Stage to insert MFA before the session is created:
      • Stage: Select default-authentication-mfa-validation (the stage configured in Step 1).
      • Order: Set to 30 (must be after user-write and before login).
  4. Click Create.

  What happens during signup:

  1. The user fills out their username, email, and password.
  2. Authentik writes the new user into the database.
  3. Authentik immediately executes the validation stage. Since the user has no registered authenticators, Authentik triggers the Configure action and presents
  the YubiKey / WebAuthn prompt (with the option to switch to TOTP).
  4. Only after completing device registration does Authentik proceed to default-enrollment-login.
  ──────
  ### Step 4: Fine-Tuning WebAuthn for YubiKeys (Optional)

  If you want to tailor the WebAuthn behavior specifically for hardware keys:

  1. Go to Flows and Stages > Stages and edit default-authenticator-webauthn-setup.
  2. Check these parameters:
      • Authenticator attachment:
          • Leave unset / empty if you want to allow both USB/NFC YubiKeys and platform biometrics (Touch ID, Windows Hello).
          • Set to cross-platform if you strictly want roaming hardware keys (like YubiKeys) and want to disallow built-in platform authenticators.
      • User verification:
          • preferred (Recommended): Allows users with YubiKey PINs to use them, while still allowing touch-only keys.
          • required: Forces users to have and enter a FIDO2 PIN on their YubiKey.
      • Resident key requirement: Leave as preferred or discouraged (standard 2FA usage).

  ──────
  ### ⚠️ Precaution: Preventing Admin Lockout

  Before testing with an unprivileged user:

  1. Do not close your current active admin browser session.
  2. Go to https://auth.<your-domain>/if/user/#/settings in your admin account and enroll your own YubiKey under MFA Devices.
  3. Open a Private / Incognito window to test:
      • Test logging in as a user without MFA to verify the prompt redirects to MFA setup.
      • Test a new user registration to confirm the signup flow halts at MFA enrollment before granting access.