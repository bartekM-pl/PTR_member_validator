<?php

require_once __DIR__ . '/includes/membership_service.php';

$result = null;
$error = null;

$hasMemberNumber = !empty($_GET['card_uid']) || !empty($_GET['member_id']) || !empty($_GET['unique_id']);

if ($hasMemberNumber) {
    try {
        $result = lookupMembership($_GET);
    } catch (Throwable $exception) {
        error_log('Membership lookup failed: ' . $exception);
        $error = 'Membership lookup is temporarily unavailable. Please try again later.';
    }
}

$pageTitle = 'Membership Verification';
$member = $result !== null && $result['found'] ? $result['member'] : null;
$verified = $result !== null && $result['verified'];
$notFound = $result !== null && !$result['found'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($pageTitle, ENT_QUOTES, 'UTF-8'); ?></title>
    <link rel="stylesheet" href="assets/css/verify.css">
</head>
<body>
    <main class="membership-verify">
        <header class="membership-verify__header">
            <h1>Membership Verification</h1>
            <p class="membership-verify__subtitle">PTR membership lookup</p>
        </header>

        <?php if ($error !== null) : ?>
            <section class="membership-card membership-card--error" role="alert">
                <h2>Error</h2>
                <p><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
            </section>
        <?php elseif ($notFound) : ?>
            <section class="membership-card membership-card--error" role="alert">
                <h2>Not Found</h2>
                <p>No membership record matches this identifier.</p>
            </section>
        <?php elseif ($verified) : ?>
            <section class="membership-card membership-verified" aria-live="polite">
                <div class="membership-card__badge membership-card__badge--verified">Verified card tap</div>
                <dl class="membership-details">
                    <div class="membership-details__row">
                        <dt>Member Number</dt>
                        <dd><?php echo htmlspecialchars((string) ($member['member_id'] ?? $member['unique_id']), ENT_QUOTES, 'UTF-8'); ?></dd>
                    </div>
                    <?php if (!empty($member['membership_type'])) : ?>
                    <div class="membership-details__row">
                        <dt>Membership Type</dt>
                        <dd><?php echo htmlspecialchars((string) $member['membership_type'], ENT_QUOTES, 'UTF-8'); ?></dd>
                    </div>
                    <?php endif; ?>
                    <?php if (!empty($member['license_level'])) : ?>
                    <div class="membership-details__row">
                        <dt>License Level</dt>
                        <dd><?php echo htmlspecialchars((string) $member['license_level'], ENT_QUOTES, 'UTF-8'); ?></dd>
                    </div>
                    <?php endif; ?>
                    <?php if (!empty($member['membership_expiration_date'])) : ?>
                    <div class="membership-details__row">
                        <dt>Expiration Date</dt>
                        <dd><?php echo htmlspecialchars((string) $member['membership_expiration_date'], ENT_QUOTES, 'UTF-8'); ?></dd>
                    </div>
                    <?php endif; ?>
                    <div class="membership-details__row">
                        <dt>Status</dt>
                        <dd>
                            <span class="status-pill <?php echo !empty($member['membership_valid']) ? 'status-pill--valid' : 'status-pill--expired'; ?>">
                                <?php echo !empty($member['membership_valid']) ? 'Valid' : 'Expired'; ?>
                            </span>
                        </dd>
                    </div>
                    <?php if (!empty($member['info'])) : ?>
                    <div class="membership-details__row">
                        <dt>Additional Info</dt>
                        <dd><?php echo nl2br(htmlspecialchars((string) $member['info'], ENT_QUOTES, 'UTF-8')); ?></dd>
                    </div>
                    <?php endif; ?>
                </dl>
            </section>
        <?php elseif ($member !== null) : ?>
            <section class="membership-card membership-unverified" aria-live="polite">
                <div class="membership-card__badge membership-card__badge--unverified">Unverified link</div>
                <p class="membership-card__note">This view does not confirm a physical card tap. Limited details are shown.</p>
                <dl class="membership-details">
                    <?php if (!empty($member['license_level'])) : ?>
                    <div class="membership-details__row">
                        <dt>License Level</dt>
                        <dd><?php echo htmlspecialchars((string) $member['license_level'], ENT_QUOTES, 'UTF-8'); ?></dd>
                    </div>
                    <?php endif; ?>
                    <div class="membership-details__row">
                        <dt>Status</dt>
                        <dd>
                            <span class="status-pill <?php echo !empty($member['membership_valid']) ? 'status-pill--valid' : 'status-pill--expired'; ?>">
                                <?php echo !empty($member['membership_valid']) ? 'Valid' : 'Expired'; ?>
                            </span>
                        </dd>
                    </div>
                </dl>
            </section>
        <?php else : ?>
            <section class="membership-card membership-card--empty">
                <h2>Look up a membership</h2>
                <p>Provide a member number in the URL, for example:</p>
                <code class="membership-example">verify.php?unique_id=0000000123</code>
            </section>
        <?php endif; ?>
    </main>
</body>
</html>
