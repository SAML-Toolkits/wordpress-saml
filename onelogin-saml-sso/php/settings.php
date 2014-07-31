<?php

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

$settings = array (

    'strict' => $opt['strict'] == 'on'? true : false,
    'debug' => $opt['debug'] == 'on'? true : false,

    'sp' => array (
        'entityId' => (!empty($opt['sp_entity_id'])? $opt['sp_entity_id'] : 'php-saml'),
        'assertionConsumerService' => array (
            'url' => plugins_url('onelogin_saml.php?acs', dirname(__FILE__))
        ),
        'singleLogoutService' => array (
            'url' => plugins_url('onelogin_saml.php?sls', dirname(__FILE__))
        ),
        'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
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
    )
);
