<?php

// Make sure we don't expose any info if called directly
if ( !function_exists( 'add_action' ) ) {
    echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
    exit;
}

require_once (dirname(__FILE__) . "/lib/Saml2/Constants.php");

$posible_nameidformat_values = array(
    'unspecified' => OneLogin_Saml2_Constants::NAMEID_UNSPECIFIED,
    'emailAddress' => OneLogin_Saml2_Constants::NAMEID_EMAIL_ADDRESS,
    'transient' => OneLogin_Saml2_Constants::NAMEID_TRANSIENT,
    'persistent' => OneLogin_Saml2_Constants::NAMEID_PERSISTENT,
    'entity' => OneLogin_Saml2_Constants::NAMEID_ENTITY,
    'encrypted' => OneLogin_Saml2_Constants::NAMEID_ENCRYPTED,
    'kerberos' => OneLogin_Saml2_Constants::NAMEID_KERBEROS,
    'x509subjecname' => OneLogin_Saml2_Constants::NAMEID_X509_SUBJECT_NAME,
    'windowsdomainqualifiedname' => OneLogin_Saml2_Constants::NAMEID_WINDOWS_DOMAIN_QUALIFIED_NAME
);
$posible_requestedauthncontext_values = array(
    'unspecified' => OneLogin_Saml2_Constants::AC_UNSPECIFIED,
    'password' => OneLogin_Saml2_Constants::AC_PASSWORD,
    'passwordprotectedtransport' => "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    'x509' => OneLogin_Saml2_Constants::AC_X509,
    'smartcard' => OneLogin_Saml2_Constants::AC_SMARTCARD,
    'kerberos' => OneLogin_Saml2_Constants::AC_KERBEROS,
);


$opt['strict'] = get_option('onelogin_saml_advanced_settings_strict_mode', 'on');
$opt['debug'] = get_option('onelogin_saml_advanced_settings_debug', 'on');
$opt['sp_entity_id'] = get_option('onelogin_saml_advanced_settings_sp_entity_id', 'php-saml');

$opt['nameIdEncrypted'] = get_option('onelogin_saml_advanced_settings_nameid_encrypted', false);
$opt['authnRequestsSigned'] = get_option('onelogin_saml_advanced_settings_authn_request_signed', false);
$opt['logoutRequestSigned'] = get_option('onelogin_saml_advanced_settings_logout_request_signed', false);
$opt['logoutResponseSigned'] = get_option('onelogin_saml_advanced_settings_logout_response_signed', false);
$opt['wantMessagesSigned'] = get_option('onelogin_saml_advanced_settings_want_message_signed', false);
$opt['wantAssertionsSigned'] = get_option('onelogin_saml_advanced_settings_want_assertion_signed', false);
$opt['wantAssertionsEncrypted'] = get_option('onelogin_saml_advanced_settings_want_assertion_encrypted', false);

$nameIDformat = get_option('onelogin_saml_advanced_nameidformat', 'unspecified');
$opt['NameIDFormat'] = $posible_nameidformat_values[$nameIDformat];


$requested_authncontext_values = get_option('onelogin_saml_advanced_requestedauthncontext', array());
if (empty($requested_authncontext_values)) {
    $opt['requestedAuthnContext'] = false;
} else {
    $opt['requestedAuthnContext'] = array();
    foreach ($requested_authncontext_values as $value) {
        if (isset($posible_requestedauthncontext_values[$value])) {
            $opt['requestedAuthnContext'][] = $posible_requestedauthncontext_values[$value];
        }
    }
}

$acs_endpoint = get_option('onelogin_saml_alternative_acs', false) ? plugins_url( 'alternative_acs.php', dirname( __FILE__ ) ) : wp_login_url() . '?saml_acs';

$settings = array (

    'strict' => $opt['strict'] == 'on'? true : false,
    'debug' => $opt['debug'] == 'on'? true : false,

    'sp' => array (
        'entityId' => (!empty($opt['sp_entity_id'])? $opt['sp_entity_id'] : 'php-saml'),
        'assertionConsumerService' => array (
            'url' => $acs_endpoint
        ),
        'singleLogoutService' => array (
            'url' => get_site_url().'/wp-login.php?saml_sls'
        ),
        'NameIDFormat' => $opt['NameIDFormat'],
        'x509cert' => get_option('onelogin_saml_advanced_settings_sp_x509cert'),
        'privateKey' => get_option('onelogin_saml_advanced_settings_sp_privatekey'),
    ),

    'idp' => array (
        'entityId' => get_option('onelogin_saml_idp_entityid'),
        'singleSignOnService' => array (
            'url' => get_option('onelogin_saml_idp_sso'),
        ),
        'singleLogoutService' => array (
            'url' => get_option('onelogin_saml_idp_slo'),
        ),
        'x509cert' => get_option('onelogin_saml_idp_x509cert'),
        'lowercaseUrlencoding' => get_option('onelogin_saml_advanced_idp_lowercase_url_encoding', false),
    ),

    'security' => array (
        'signMetadata' => false,
        'nameIdEncrypted' => $opt['nameIdEncrypted'] == 'on'? true: false,
        'authnRequestsSigned' => $opt['authnRequestsSigned'] == 'on'? true: false,
        'logoutRequestSigned' => $opt['logoutRequestSigned'] == 'on'? true: false,
        'logoutResponseSigned' => $opt['logoutResponseSigned'] == 'on'? true: false,
        'wantMessagesSigned' => $opt['wantMessagesSigned'] == 'on'? true: false,
        'wantAssertionsSigned' => $opt['wantAssertionsSigned'] == 'on'? true: false,
        'wantAssertionsEncrypted' => $opt['wantAssertionsEncrypted'] == 'on'? true: false,
        'requestedAuthnContext' => $opt['requestedAuthnContext'],
    )
);
