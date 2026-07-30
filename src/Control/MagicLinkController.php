<?php

namespace XD\MagicLinkLogin\Control;

use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\Email\Email;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Security;
use SilverStripe\Security\SecurityToken;
use XD\MagicLinkLogin\Model\MagicLinkToken;
use XD\MagicLinkLogin\Service\SessionScope;

/**
 * Handles the two steps of a magic-link login:
 *
 *   GET  /magic-link/click/{token}   - resolves the emailed token and either completes login directly
 *                                       or (default) sends an emailed verification code and shows the
 *                                       code-entry form.
 *   POST /magic-link/verify          - verifies the submitted code and completes login.
 *
 * Login is always completed via SilverStripe's own IdentityStore — this module never maintains its own
 * parallel session/token-auth mechanism, so everything downstream (Security::getCurrentUser(), canView/
 * canEdit checks, login history) behaves exactly as it would for any other login method.
 */
class MagicLinkController extends Controller
{
    private static array $allowed_actions = [
        'click',
        'verify',
    ];

    private static bool $require_email_confirmation = true;

    private static int $code_period = 600;

    private static int $code_length = 6;

    private static int $max_code_attempts = 5;

    private const PENDING_SESSION_KEY = 'XDMagicLinkLogin.PendingTokenID';

    /**
     * This controller is wired up through Director.rules ('magic-link//$Action/$ID') rather than a
     * url_segment, so the RequestHandler default Link() has nothing to build from and errors. Build
     * the link from the known route base instead, absolute so form actions resolve correctly
     * regardless of the current request path.
     */
    public function Link($action = null): string
    {
        return Director::absoluteURL(Controller::join_links('magic-link', $action));
    }

    public function click(HTTPRequest $request): HTTPResponse
    {
        $rawToken = $request->param('ID');
        $token = $rawToken ? MagicLinkToken::findValidByRawToken($rawToken) : null;

        if (!$token) {
            return $this->errorResponse(
                _t(__CLASS__ . '.LINK_INVALID', 'This link is invalid or has expired. Please request a new one.'),
                410
            );
        }

        $targetMember = $token->Member();
        $currentMember = Security::getCurrentUser();

        // Logged in as someone else — force logout before proceeding, never mix sessions.
        if ($currentMember && (int) $currentMember->ID !== (int) $targetMember->ID) {
            $this->getIdentityStore()->logOut($request);
            $currentMember = null;
        }

        // Already logged in as the same Member — no need to re-authenticate, just extend the scope.
        if ($currentMember) {
            SessionScope::extend($token->getScopeArray(), $request);
            return $this->redirect($token->RedirectURL);
        }

        if (!$this->config()->get('require_email_confirmation')) {
            $this->completeLogin($token, $request);
            return $this->redirect($token->RedirectURL);
        }

        $code = $token->generateCode(
            (int) $this->config()->get('code_length'),
            (int) $this->config()->get('code_period')
        );
        $this->sendCodeEmail($targetMember->Email, $code);

        $request->getSession()->set(static::PENDING_SESSION_KEY, $token->ID);

        return $this->renderVerifyForm($targetMember->Email);
    }

    public function verify(HTTPRequest $request): HTTPResponse
    {
        if (!SecurityToken::inst()->checkRequest($request)) {
            return $this->errorResponse(
                _t(__CLASS__ . '.CSRF_FAILURE', 'Your session timed out. Please use the link from your email again.'),
                403
            );
        }

        $tokenID = $request->getSession()->get(static::PENDING_SESSION_KEY);
        $token = $tokenID ? MagicLinkToken::get()->byID($tokenID) : null;

        if (!$token || !$token->exists() || $token->isExpired()) {
            $request->getSession()->clear(static::PENDING_SESSION_KEY);
            return $this->errorResponse(
                _t(__CLASS__ . '.LINK_INVALID', 'This link is invalid or has expired. Please request a new one.'),
                410
            );
        }

        $submittedCode = (string) $request->postVar('Code');
        $maxAttempts = (int) $this->config()->get('max_code_attempts');

        if (!$token->verifyCode($submittedCode, $maxAttempts)) {
            return $this->renderVerifyForm(
                $token->Member()->Email,
                _t(__CLASS__ . '.CODE_INVALID', 'That code is incorrect or has expired.')
            );
        }

        $this->completeLogin($token, $request);
        $request->getSession()->clear(static::PENDING_SESSION_KEY);

        return $this->redirect($token->RedirectURL);
    }

    private function completeLogin(MagicLinkToken $token, HTTPRequest $request): void
    {
        $this->getIdentityStore()->logIn($token->Member(), false, $request);
        SessionScope::extend($token->getScopeArray(), $request);
    }

    private function sendCodeEmail(string $to, string $code): void
    {
        Email::create()
            ->setTo($to)
            ->setSubject(_t(__CLASS__ . '.CODE_EMAIL_SUBJECT', 'Your verification code'))
            ->setData(['Code' => $code])
            ->setHTMLTemplate('XD/MagicLinkLogin/Email/VerificationCode')
            ->send();
    }

    private function renderVerifyForm(string $email, ?string $error = null): HTTPResponse
    {
        $html = $this->renderWith('XD/MagicLinkLogin/Control/MagicLinkController_verify', [
            'ObfuscatedEmail' => $this->obfuscateEmail($email),
            'Error'           => $error,
            'SecurityID'      => SecurityToken::inst()->getValue(),
            'VerifyLink'      => $this->Link('verify'),
        ]);

        // renderWith() returns a DBHTMLText; wrap it so the declared HTTPResponse return type holds.
        return HTTPResponse::create((string) $html);
    }

    private function obfuscateEmail(string $email): string
    {
        [$local, $domain] = array_pad(explode('@', $email, 2), 2, '');
        $visible = mb_substr($local, 0, 1);
        return $visible . str_repeat('*', max(mb_strlen($local) - 1, 3)) . '@' . $domain;
    }

    private function errorResponse(string $message, int $statusCode): HTTPResponse
    {
        return HTTPResponse::create($message, $statusCode);
    }

    private function getIdentityStore(): IdentityStore
    {
        return Injector::inst()->get(IdentityStore::class);
    }
}
