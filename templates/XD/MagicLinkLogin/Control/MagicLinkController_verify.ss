<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title><%t XD\MagicLinkLogin\Control\MagicLinkController.VERIFY_TITLE 'Enter your verification code' %></title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 2rem; }
        .card { max-width: 360px; margin: 4rem auto; background: #fff; border-radius: 8px; padding: 2rem; box-shadow: 0 1px 4px rgba(0,0,0,0.1); }
        h1 { font-size: 1.25rem; margin: 0 0 0.5rem; }
        p { color: #555; font-size: 0.9rem; }
        input[type="text"] { width: 100%; box-sizing: border-box; font-size: 1.5rem; letter-spacing: 0.3em; text-align: center; padding: 0.75rem; margin: 1rem 0; border: 1px solid #ccc; border-radius: 4px; }
        button { width: 100%; padding: 0.75rem; background: #000; color: #fff; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; }
        .error { color: #c62828; font-size: 0.85rem; margin-bottom: 1rem; }
    </style>
</head>
<body>
    <div class="card">
        <h1><%t XD\MagicLinkLogin\Control\MagicLinkController.VERIFY_TITLE 'Enter your verification code' %></h1>
        <p><%t XD\MagicLinkLogin\Control\MagicLinkController.VERIFY_SENT_TO 'We sent a code to {email}' email=$ObfuscatedEmail %></p>

        <% if $Error %>
            <div class="error">$Error</div>
        <% end_if %>

        <form method="post" action="$VerifyLink">
            <input type="hidden" name="SecurityID" value="$SecurityID">
            <input type="text" name="Code" inputmode="numeric" autocomplete="one-time-code" autofocus required>
            <button type="submit"><%t XD\MagicLinkLogin\Control\MagicLinkController.VERIFY_SUBMIT 'Continue' %></button>
        </form>
    </div>
</body>
</html>
