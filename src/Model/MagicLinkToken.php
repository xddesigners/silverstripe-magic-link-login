<?php

namespace XD\MagicLinkLogin\Model;

use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\Member;

/**
 * A single-purpose, time-bound link that grants a specific Member access via XD\MagicLinkLogin\Control\MagicLinkController.
 *
 * Only a hash of the raw token is ever persisted (mirrors how SilverStripe stores password-reset tokens) so a
 * database leak alone cannot be used to construct a working link.
 *
 * @property string $TokenHash
 * @property string $RedirectURL
 * @property string $Scope
 * @property string $Expires
 * @property string $CodeHash
 * @property string $CodeExpires
 * @property int $CodeAttempts
 * @property int $MemberID
 * @method Member Member()
 */
class MagicLinkToken extends DataObject
{
    private static $table_name = 'XD_MagicLinkToken';

    private static $db = [
        'TokenHash'    => 'Varchar(64)',
        'RedirectURL'  => 'Text',
        'Scope'        => 'Text',
        'Expires'      => 'Datetime',
        'CodeHash'     => 'Varchar(255)',
        'CodeExpires'  => 'Datetime',
        'CodeAttempts' => 'Int',
    ];

    private static $has_one = [
        'Member' => Member::class,
    ];

    private static $indexes = [
        'TokenHash' => true,
    ];

    /**
     * Create a new token for the given Member, valid for `link_period` seconds (see MagicLinkController config).
     *
     * @param Member $member
     * @param string $redirectURL Where to send the browser once login completes.
     * @param array $scope Array of ['ClassName' => string, 'ID' => int, 'canView' => bool, 'canEdit' => bool]
     * @param int $linkPeriod Seconds until this token expires.
     * @return array{0: self, 1: string} The created record and the raw (unhashed) token to embed in the URL.
     */
    public static function createFor(Member $member, string $redirectURL, array $scope, int $linkPeriod): array
    {
        $rawToken = bin2hex(random_bytes(32));

        $token = static::create();
        $token->MemberID = $member->ID;
        $token->TokenHash = static::hashToken($rawToken);
        $token->RedirectURL = $redirectURL;
        $token->Scope = json_encode($scope);
        $token->Expires = DBDatetime::create()->setValue(time() + $linkPeriod)->getValue();
        $token->write();

        return [$token, $rawToken];
    }

    /**
     * Look up a non-expired token by its raw (unhashed) value.
     */
    public static function findValidByRawToken(string $rawToken): ?self
    {
        /** @var self|null $token */
        $token = static::get()->filter('TokenHash', static::hashToken($rawToken))->first();

        if (!$token || !$token->exists() || $token->isExpired()) {
            return null;
        }

        return $token;
    }

    public function isExpired(): bool
    {
        return !$this->Expires || strtotime($this->Expires) < time();
    }

    /**
     * @return array<int, array{ClassName: string, ID: int, canView: bool, canEdit: bool}>
     */
    public function getScopeArray(): array
    {
        $decoded = json_decode((string) $this->Scope, true);
        return is_array($decoded) ? $decoded : [];
    }

    /**
     * Generate and store a fresh verification code, resetting any previous one for this token.
     * Only the hash is persisted; the raw code is returned for the caller to email.
     */
    public function generateCode(int $codeLength, int $codePeriod): string
    {
        $code = static::randomNumericCode($codeLength);

        $this->CodeHash = password_hash($code, PASSWORD_DEFAULT);
        $this->CodeExpires = DBDatetime::create()->setValue(time() + $codePeriod)->getValue();
        $this->CodeAttempts = 0;
        $this->write();

        return $code;
    }

    /**
     * Verify a submitted code against the currently stored one. Tracks failed attempts so repeated
     * guessing invalidates the code after `$maxAttempts` failures.
     */
    public function verifyCode(string $submittedCode, int $maxAttempts): bool
    {
        if (!$this->CodeHash || !$this->CodeExpires) {
            return false;
        }

        if (strtotime($this->CodeExpires) < time()) {
            return false;
        }

        if ($this->CodeAttempts >= $maxAttempts) {
            return false;
        }

        if (password_verify($submittedCode, $this->CodeHash)) {
            return true;
        }

        $this->CodeAttempts++;
        $this->write();

        return false;
    }

    private static function hashToken(string $rawToken): string
    {
        return hash('sha256', $rawToken);
    }

    private static function randomNumericCode(int $length): string
    {
        $max = (10 ** $length) - 1;
        return str_pad((string) random_int(0, $max), $length, '0', STR_PAD_LEFT);
    }
}
