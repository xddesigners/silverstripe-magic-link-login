# silverstripe-magic-link-login

Passwordless login via a unique emailed link, with an optional emailed verification code as a second
factor, and per-login session scoping so each login only grants access to the specific record(s) it was
issued for.

Login is always completed through SilverStripe's own `IdentityStore` — this module never maintains a
parallel session/token-auth system. Once a magic link (and, by default, its verification code) is
consumed, the visitor is logged in exactly as if they'd used any other authenticator: `Security::
getCurrentUser()` is populated, `Member.LastLogin` is updated, and it shows up in the normal login
history.

## Why session scoping?

A full login grants the full privileges of whichever `Member` record it resolves to — not just the one
thing the link was issued for. If that Member is also a rater on other records, or has any other access
on their account, a plain full login would hand out all of that too. `SessionScope` closes that gap: each
magic link declares which record(s) it's allowed to touch, and that restriction is enforced independently
of (and in addition to) whatever the Member's account would otherwise permit — for the lifetime of that
browser session only.

## Installation

```bash
composer require xddesigners/silverstripe-magic-link-login
```

## Generating a link

```php
use XD\MagicLinkLogin\Service\MagicLinkService;

$url = MagicLinkService::generateFor(
    $member,
    '/sessions/edit/123', // where to land once login completes
    [
        ['ClassName' => RatingSession::class, 'ID' => 123],
        // canView/canEdit both default to true if omitted
    ]
);

// email $url to $member
```

Each call creates a new token, independent of any others already issued to the same Member — a Member
can hold several outstanding magic links at once (e.g. invited to review three separate sessions). Using
one does not consume or affect the others.

## Enforcing scope in your own models

```php
use XD\MagicLinkLogin\Service\SessionScope;

public function canView($member = null)
{
    $scoped = SessionScope::check($this, 'canView');
    if ($scoped !== null) {
        return $scoped; // this session is scoped — defer entirely to the scope decision
    }

    return parent::canView($member); // unscoped session — normal permission logic applies
}
```

`SessionScope::check()` returns `null` when the current session isn't scoped at all (e.g. a normal SAML/
password login), so existing permission logic for non-magic-link users is unaffected.

## Behaviour on click

- **Different Member already logged in** → that session is logged out before the new login proceeds. No
  mixing of identities in one browser session.
- **Same Member already logged in** → no re-authentication; the link's scope is merged into the existing
  session (via `SessionScope::extend()`) and the browser is redirected straight to the target.
- **Not logged in** → if `require_email_confirmation` is on (default), a one-time code is emailed and a
  plain code-entry form is shown; if off, login completes immediately from the link alone.

## Configuration

```yaml
XD\MagicLinkLogin\Service\MagicLinkService:
  link_period: 259200 # seconds a generated link stays valid (default: 72 hours)

XD\MagicLinkLogin\Control\MagicLinkController:
  require_email_confirmation: true # set false to skip the emailed code entirely
  code_period: 600                 # seconds a sent code stays valid (default: 10 minutes)
  code_length: 6                   # digits in the emailed code
  max_code_attempts: 5             # incorrect guesses allowed before the code is invalidated
```

## Notes

- No React/CMS-admin UI is involved — the code-entry step is a plain, unstyled server-rendered form
  (`templates/XD/MagicLinkLogin/Control/MagicLinkController_verify.ss`), overridable like any other
  SilverStripe template. This is deliberate: the formal `silverstripe/mfa` `MethodInterface` machinery
  assumes a Member permanently enrolls in a method ahead of time, which doesn't fit a one-off invite
  recipient who never "sets up" anything.
- Only a hash of each token (and each code) is ever persisted — a database leak alone cannot be used to
  reconstruct a working link or code.
- The scope list itself lives entirely in the server-side PHP session, the same mechanism SilverStripe's
  own login flows use — nothing is ever exposed to the client for a user to tamper with.
