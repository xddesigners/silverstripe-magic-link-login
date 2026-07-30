<?php

namespace XD\MagicLinkLogin\Service;

use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Security\Member;
use XD\MagicLinkLogin\Model\MagicLinkToken;

/**
 * Public entry point for consuming applications: generate a magic-link URL for a Member, scoped to
 * whichever records that login should be allowed to touch.
 *
 * This is the only class a consuming app needs to call directly.
 */
class MagicLinkService
{
    use Configurable;

    private static int $link_period = 259200; // 72 hours, mirrors MagicLinkController default

    /**
     * @param Member $member Who this link authenticates as.
     * @param string $redirectURL Where the browser should land once login completes. Relative to the site root.
     * @param array<int, array{ClassName: string, ID: int, canView?: bool, canEdit?: bool}> $scope
     *   Records this login is allowed to touch. Leave empty for an unrestricted login (rarely what you want
     *   for an invite-style link — normally this should list at least the one record the link is for).
     * @return string Absolute URL to email to the Member.
     */
    public static function generateFor(Member $member, string $redirectURL, array $scope = []): string
    {
        $linkPeriod = (int) static::config()->get('link_period');

        [, $rawToken] = MagicLinkToken::createFor($member, $redirectURL, $scope, $linkPeriod);

        return Director::absoluteURL('magic-link/click/' . $rawToken);
    }
}
