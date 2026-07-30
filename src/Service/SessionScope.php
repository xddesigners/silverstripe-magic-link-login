<?php

namespace XD\MagicLinkLogin\Service;

use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\ORM\DataObject;

/**
 * Restricts what an authenticated session is allowed to view/edit to a specific, explicit list of records,
 * regardless of what the underlying Member's account would otherwise be permitted to do.
 *
 * Stored entirely server-side via the PHP session (same mechanism SilverStripe's own login/MFA flows use) —
 * nothing here is ever serialised to the client, so there is no session state for a user to tamper with directly.
 * A session with no scope set at all is unrestricted; check() returns null in that case so callers can fall
 * through to their normal permission logic.
 */
class SessionScope
{
    private const SESSION_KEY = 'XDMagicLinkLogin.Scope';

    /**
     * Replace any existing scope for the current session with the given entries.
     *
     * @param array<int, array{ClassName: string, ID: int, canView?: bool, canEdit?: bool}> $entries
     */
    public static function grant(array $entries, ?HTTPRequest $request = null): void
    {
        $session = static::session($request);
        if (!$session) {
            return;
        }
        $session->set(static::SESSION_KEY, static::normalise($entries));
    }

    /**
     * Add entries to whatever scope is already active for the current session, without discarding it.
     * If an entry for the same ClassName+ID already exists, it is replaced (not duplicated).
     *
     * @param array<int, array{ClassName: string, ID: int, canView?: bool, canEdit?: bool}> $entries
     */
    public static function extend(array $entries, ?HTTPRequest $request = null): void
    {
        $session = static::session($request);
        if (!$session) {
            return;
        }
        $existing = $session->get(static::SESSION_KEY) ?? [];

        $merged = [];
        foreach (array_merge($existing, static::normalise($entries)) as $entry) {
            $merged[$entry['ClassName'] . ':' . $entry['ID']] = $entry;
        }

        $session->set(static::SESSION_KEY, array_values($merged));
    }

    /**
     * @param DataObject $object
     * @param 'canView'|'canEdit' $permission
     * @return bool|null True/false if this session is scoped, null if the session is unrestricted.
     */
    public static function check(DataObject $object, string $permission, ?HTTPRequest $request = null): ?bool
    {
        $session = static::session($request);
        if (!$session) {
            return null; // no session context (CLI) → unrestricted
        }
        $scope = $session->get(static::SESSION_KEY);

        if ($scope === null) {
            return null;
        }

        foreach ($scope as $entry) {
            if ($entry['ClassName'] === $object->ClassName && (int) $entry['ID'] === (int) $object->ID) {
                return (bool) ($entry[$permission] ?? true);
            }
        }

        // Session is scoped, but this object isn't in the granted list — explicit deny.
        return false;
    }

    public static function clear(?HTTPRequest $request = null): void
    {
        $session = static::session($request);
        if (!$session) {
            return;
        }
        $session->clear(static::SESSION_KEY);
    }

    /**
     * @param array<int, array{ClassName: string, ID: int, canView?: bool, canEdit?: bool}> $entries
     * @return array<int, array{ClassName: string, ID: int, canView: bool, canEdit: bool}>
     */
    private static function normalise(array $entries): array
    {
        return array_map(static function (array $entry): array {
            return [
                'ClassName' => $entry['ClassName'],
                'ID'        => (int) $entry['ID'],
                'canView'   => (bool) ($entry['canView'] ?? true),
                'canEdit'   => (bool) ($entry['canEdit'] ?? true),
            ];
        }, $entries);
    }

    private static function session(?HTTPRequest $request)
    {
        // No request outside an HTTP context (CLI tasks, dev/build) — return null so callers treat
        // the session as unrestricted rather than crashing on Controller::curr() being null.
        $controller = Controller::curr();
        $request = $request ?? ($controller ? $controller->getRequest() : null);
        return $request ? $request->getSession() : null;
    }
}
