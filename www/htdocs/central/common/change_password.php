<?php
/*
 * Script: change_password.php
 * Location: /central/common/change_password.php
 * Author: Roger Craveiro Guilherme
 * Description: Dedicated page for authenticated users to change their own password. This script is designed to be secure and user-friendly, providing a straightforward interface for password updates while ensuring that only authorized users can access it. It includes CSRF protection, input validation, and clear feedback messages for the user.
 * Date: 2026-09-07
 */

session_start();
require_once("get_post.php");

// 1. Setup Database and Config Paths
if (isset($arrHttp["db_path"])) {
    $_SESSION["DATABASE_DIR"] = $arrHttp["db_path"];
}
require_once("../config.php");

// 2. Localization Setup
if (isset($_SESSION["lang"])) {
    $arrHttp["lang"] = $_SESSION["lang"];
} else {
    $arrHttp["lang"] = $lang;
    $_SESSION["lang"] = $lang;
}
include("../lang/admin.php");
include("../lang/lang.php");

// Set dynamic charset to prevent encoding mismatch (ISO-8859-1 vs UTF-8)
$sys_charset = !empty($meta_encoding) ? $meta_encoding : 'UTF-8';

// 3. Access Control: Verify active session (Do not call VerificarUsuario() here)
if (!isset($_SESSION["login"]) || empty($_SESSION["login"])) {
    header("Location: logout.php");
    exit;
}

// 4. Refuse Emergency User and LDAP
// Emergency users do not have an MFN in their active session
if (!isset($_SESSION["mfn_admin"]) || $_SESSION["mfn_admin"] == "") {
    echo "<script>alert('" . addslashes($msgstr["emergnochgpwd"]) . "'); window.location.href='inicio.php';</script>";
    exit;
}
if (isset($use_ldap) && $use_ldap) {
    echo "<script>alert('" . addslashes($msgstr["nochgpwdldap"]) . "'); window.location.href='inicio.php';</script>";
    exit;
}

// 5. Anti-CSRF Token Generation
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

$error_message = "";

// 6. Pre-flight Middleware: Intercept POST before delegating to inicio.php
if (isset($arrHttp['Opcion']) && $arrHttp['Opcion'] === 'chgpsw') {
    $post_csrf = $arrHttp['csrf_token'] ?? '';

    // Validate CSRF
    if (!hash_equals($csrf_token, $post_csrf)) {
        $error_message = $msgstr["csrf_error"] ?? "Security token validation failed. Request blocked.";
    } else {
        $new_password = trim($arrHttp['new_password'] ?? '');
        $confirm_password = trim($arrHttp['confirm_password'] ?? '');

        // Backend Complexity & Match Checks
        if ($new_password !== $confirm_password) {
            $error_message = $msgstr["passconfirm"];
        } elseif (!preg_match('/^[0-9a-zA-Z.,!@#$%^&*?_~\\\\()-]+$/', $new_password)) {
            $error_message = $msgstr["validpwdchars"];
        } else {
            // Validation Passed. Delegate to ABCD's core native handler.
            require_once("inicio.php");
            exit;
        }
    }
}

$css_name = (isset($css_name)) ? $css_name . "/" : "";

include("header.php");
include("institutional_info.php");
?>

<div class="sectionInfo">
    <div class="breadcrumb">
        <?php echo htmlspecialchars($msgstr["chgpass"] ?? 'Change Password', ENT_QUOTES, $sys_charset); ?>
    </div>
    <div class="actions"></div>
    <div class="spacer">&#160;</div>
</div>

<!-- Main Content Area -->
<div class="middle login">
    <!-- Reutilizando o container nativo de login -->
    <div class="loginForm">
        <div class="boxContent">

            <h3 class="mb-3 color-gray-800" style="border-bottom: 1px solid #eee; padding-bottom: 10px;">
                <i class="fas fa-shield-alt color-blue"></i>
                <?php echo htmlspecialchars($msgstr["chgpass"] ?? 'Change Password', ENT_QUOTES, $sys_charset); ?>
            </h3>

            <?php if (!empty($error_message)): ?>
                <!-- Reutilizando a classe .alert nativa do ABCD -->
                <div class="alert mb-3">
                    <?php echo htmlspecialchars($error_message, ENT_QUOTES, $sys_charset); ?>
                </div>
            <?php endif; ?>

            <form name="administra" id="frmChangePassword" action="change_password.php" method="POST" onsubmit="return validateFrontend();">
                <input type="hidden" name="Opcion" value="chgpsw">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, $sys_charset); ?>">
                <input type="hidden" name="login" value="<?php echo htmlspecialchars($arrHttp["login"] ?? $_SESSION["login"], ENT_QUOTES, $sys_charset); ?>">

                <p>
                    <?php echo htmlspecialchars($name ?? $_SESSION["nombre"] ?? '', ENT_QUOTES, $sys_charset); ?>
                    <small>(<?php echo htmlspecialchars($profile ?? $_SESSION["profile"] ?? '', ENT_QUOTES, $sys_charset); ?>)</small>
                </p>

                <!-- formRow e textEntry dentro do loginForm forçam o layout 100% -->
                <div class="formRow mb-3">
                    <label for="current_pwd" class="color-gray-700 font-weight-bold">
                        <?php echo htmlspecialchars($msgstr["actualpass"] ?? 'Current Password', ENT_QUOTES, $sys_charset); ?>
                    </label>
                    <div style="position: relative;">
                        <input type="password" name="password" id="current_pwd" class="textEntry" required autocomplete="current-password" style="padding-right: 35px;">
                        <i class="far fa-eye" onclick="toggleVisibility('current_pwd', this)" style="position: absolute; right: 10px; top: 70%; transform: translateY(-50%); cursor: pointer; color: var(--abcd-gray-600);" title="<?php echo htmlspecialchars($msgstr["ver"] ?? 'Show', ENT_QUOTES, $sys_charset); ?>"></i>
                    </div>
                </div>

                <div class="formRow mb-3">
                    <label for="new_pwd" class="color-gray-700 font-weight-bold">
                        <?php echo htmlspecialchars($msgstr["newpass"] ?? 'New Password', ENT_QUOTES, $sys_charset); ?>
                    </label>
                    <div style="position: relative;">
                        <input type="password" name="new_password" id="new_pwd" class="textEntry" required autocomplete="new-password" style="padding-right: 35px;">
                        <i class="far fa-eye" onclick="toggleVisibility('new_pwd', this)" style="position: absolute; right: 10px; top: 70%; transform: translateY(-50%); cursor: pointer; color: var(--abcd-gray-600);" title="<?php echo htmlspecialchars($msgstr["ver"] ?? 'Show', ENT_QUOTES, $sys_charset); ?>"></i>
                    </div>
                    <span class="color-gray-500" style="font-size: 0.85em; display: block; margin-top: 5px;">
                        <?php echo htmlspecialchars($msgstr["pwd_policy_help"] ?? "Allowed: letters, numbers, basic symbols. No spaces.", ENT_QUOTES, $sys_charset); ?>
                    </span>
                </div>

                <div class="formRow mb-4">
                    <label for="confirm_pwd" class="color-gray-700 font-weight-bold">
                        <?php echo htmlspecialchars($msgstr["confirmpass"] ?? 'Confirm Password', ENT_QUOTES, $sys_charset); ?>
                    </label>
                    <div style="position: relative;">
                        <input type="password" name="confirm_password" id="confirm_pwd" class="textEntry" required autocomplete="new-password" style="padding-right: 35px;">
                        <i class="far fa-eye" onclick="toggleVisibility('confirm_pwd', this)" style="position: absolute; right: 10px; top: 70%; transform: translateY(-50%); cursor: pointer; color: var(--abcd-gray-600);" title="<?php echo htmlspecialchars($msgstr["ver"] ?? 'Show', ENT_QUOTES, $sys_charset); ?>"></i>
                    </div>
                </div>

                <div class="formRow mt-4" style="text-align: right;">
                    <a class="bt bt-light color-white p-2" href="javascript:history.back()">
                        <i class="fas fa-times"></i> <?php echo htmlspecialchars($msgstr["cancelar"] ?? 'Cancel', ENT_QUOTES, $sys_charset); ?>
                    </a>

                    <button type="submit" class="bt bt-blue color-white p-2">
                        <i class="fas fa-save"></i> <?php echo htmlspecialchars($msgstr["chgpass"] ?? 'Change', ENT_QUOTES, $sys_charset); ?>
                    </button>
                </div>

            </form>
        </div>
    </div>
</div>

<script>
    function toggleVisibility(fieldId, iconEl) {
        var field = document.getElementById(fieldId);
        if (field.type === "password") {
            field.type = "text";
            iconEl.classList.remove("fa-eye");
            iconEl.classList.add("fa-eye-slash");
        } else {
            field.type = "password";
            iconEl.classList.remove("fa-eye-slash");
            iconEl.classList.add("fa-eye");
        }
    }

    function validateFrontend() {
        var newPwd = Trim(document.getElementById('new_pwd').value);
        var confPwd = Trim(document.getElementById('confirm_pwd').value);

        if (newPwd !== confPwd) {
            alert("<?php echo addslashes($msgstr["passconfirm"] ?? 'Passwords do not match'); ?>");
            return false;
        }

        var allowedChars = /^[0-9a-zA-Z\.,!@#$%^&*?_~\\\-()]+$/;
        if (!allowedChars.test(newPwd)) {
            alert("<?php echo addslashes($msgstr["validpwdchars"] ?? 'Invalid characters'); ?>");
            return false;
        }
        return true;
    }
</script>

<?php include("footer.php"); ?>