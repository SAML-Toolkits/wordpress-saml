<?php
/**
 * This file contains the class Error_Codes
 * This class contains the error codes and their descriptions.
 *
 * @package miniorange-saml-20-single-sign-on/constant
 */

namespace MOSAML\SRC\Constant;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Defines Error Codes used in the plugin.
 */
class Error_Codes_Enums {
	const ERROR_MESSAGE = 'We could not process this request. Please contact your administrator with the mentioned error code.';
	/**
	 * A map for error codes and their description.
	 *
	 * @var array
	 */
	public static $error_codes = array(
		'WPSAMLERR001' => array(
			'code'            => 'WPSAMLERR001',
			'description'     => 'The Free Version of the plugin does not support encrypted assertion and IDP is sending Encrypted Assertion.',
			'fix'             => 'Please turn off assertion encryption in your IDP to test the SSO flow.',
			'cause'           => 'Encrypted Assertion From IDP',
			'test_config_msg' => 'Your IdP is sending encrypted assertion which is not supported in free version.',
		),
		'WPSAMLERR002' => array(
			'code'            => 'WPSAMLERR002',
			'description'     => 'This error occurs when the plugin can\'t find the NameID attribute in the IDP response.',
			'fix'             => 'Please configure your IDP to send a NameID attribute. If it is already configured then the user with which you are trying might have the blank NameID mapped attribute.',
			'cause'           => 'NameID missing',
			'test_config_msg' => 'NameID may not be configured at the IDP or the user does not have a valid NameID value.',
		),
		'WPSAMLERR003' => array(
			'code'            => 'WPSAMLERR003',
			'description'     => 'No signature was found in the SAML Response or Assertion.',
			'fix'             => 'It is required by the SAML 2.0 standard that either the response or assertion is signed. Please enable the same in your IDP.',
			'cause'           => 'Unsigned Response or Assertion',
			'test_config_msg' => 'No signature found in SAML Response or Assertion. Please sign at least one of them.',
		),
		'WPSAMLERR004' => array(
			'code'            => 'WPSAMLERR004',
			'description'     => 'This error occurs  when certificate present in SAML Response does not match with the certificate configured in the plugin.',
			'fix'             => '<ol><li>Copy paste the certificate provided above in X.509 Certificate field for the respective IDP under IDP Configuration tab. </li><li>If issue persists disable <b>Character encoding</b> for the respective IDP under IDP Configuration tab.</li></ol>',
			'cause'           => 'Mismatch in Certificate',
			'test_config_msg' => 'X.509 Certificate field in plugin does not match the certificate found in SAML Response.',
		),
		'WPSAMLERR005' => array(
			'code'            => 'WPSAMLERR005',
			'description'     => 'This error is displayed when there is an issue in creating user in WordPress.',
			'fix'             => 'There has been some issue with user creation in wordpress copy the error message and reach out us at <a href="mailto:samlsupport@xecurify.com">samlsupport@xecurify.com</a> with your registered email.',
			'cause'           => 'User Creation Failed',
			'test_config_msg' => 'Something went wrong while creating the user. Please reach out to us with the debug logs.',
		),
		'WPSAMLERR006' => array(
			'code'            => 'WPSAMLERR006',
			'description'     => 'This error is Displayed when IDP returns a status code other than SUCCESS.<br/> The following are some of the common Status Code errors that you might encounter:<br/>
                                    <u>Requester:</u> The IDP sends this status code when it doesn\'t like the SAML request. For example: The IDP was expecting a signed request but it received an unsigned one.<br/>
                                    <u>Responder:</u> The IDP side of configuration is not correct. For ex: The ACS URL is not properly configured at the IDP end.<br/>
                                    <u>AuthnFailed:</u> Some IDPs send this status code if the signature verification of the SAML Request fails.',
			'fix'             => 'You will need to double check the configuration between your IDP and SP to fix this issue.',
			'cause'           => 'Invalid Status Code',
			'test_config_msg' => 'Identity Provider has sent status code other than success in SAML Response. Please check IdP logs.',
		),
		'WPSAMLERR007' => array(
			'code'            => 'WPSAMLERR007',
			'description'     => 'This can happen when your SP clock is behind the IDP clock.',
			'fix'             => 'You will need to sync the time between your IDP and SP or you can turn off the <b>Assertion Time Validity</b> toggle for the respective IDP in the IDP Configuration tab.',
			'cause'           => 'SP clock is behind IDP',
			'test_config_msg' => '',
		),
		'WPSAMLERR008' => array(
			'code'            => 'WPSAMLERR008',
			'description'     => 'This can happen when your SP clock is ahead of the IDP clock.',
			'fix'             => 'You will need to sync the time between your IDP and SP or you can turn off the <b>Assertion Time Validity</b> toggle for the respective IDP in the IDP Configuration tab.',
			'cause'           => 'SP clock is ahead of IDP',
			'test_config_msg' => '',
		),
		'WPSAMLERR009' => array(
			'code'            => 'WPSAMLERR009',
			'description'     => 'This error indicates that the Audience URI is not correctly configured at your Identity Provider.',
			'fix'             => '<ul style="list-style: none;"><li style="list-style-type: none;">Copy the Audience URI configured in the Identity Provider from above and paste it into the SP EntityID/Issuer field in the Plugin\'s settings. </li><li style="list-style-type: none; font-weight: bold; text-align: center; margin: 10px 0;">OR </li><li style="list-style-type: none;">Copy the Audience URI configured in the plugin from above and paste it into the Audience URI field in the Identity Provider.</li></ul>',
			'cause'           => 'Invalid Audience URI',
			'test_config_msg' => 'The value of Audience URI in the plugin settings does not match the value of Audience URI received from the Identity Provider.',
		),
		'WPSAMLERR010' => array(
			'code'            => 'WPSAMLERR010',
			'description'     => 'This happens when you have configured wrong IDP Entity ID in the plugin.',
			'fix'             => 'To fix this navigate to IDP Configuration tab and paste the correct IDP Entity ID in the required field for the respective IDP.',
			'cause'           => 'Wrong IDP Entity ID',
			'test_config_msg' => 'IdP Entity ID configured and the one found in SAML Response do not match',
		),
		'WPSAMLERR011' => array(
			'code'            => 'WPSAMLERR011',
			'description'     => 'This error is displayed when the Username value is greater than 60 characters.',
			'fix'             => 'To fix this issue, please configure your IDP to send a valid email address as the NameID value, which should be less than 60 characters in length.',
			'cause'           => 'Username length limit exceeded',
			'test_config_msg' => 'The NameID value is greater than 60 characters in length. Please configure your IDP to send a proper NameID value.',
		),
		'WPSAMLERR012' => array(
			'code'            => 'WPSAMLERR012',
			'description'     => 'This error occurs when certificate present in SAML Response does not match with the certificate configured in the plugin after encoding.',
			'fix'             => 'To fix this error, turn off the <b>Character encoding</b> toggle for the respective IDP in the IDP Configuration tab.',
			'cause'           => 'Mismatch in Certificate',
			'test_config_msg' => 'X.509 Certificate in plugin does not match the certificate found in SAML Response due to the character encoding.',
		),
		'WPSAMLERR013' => array(
			'code'            => 'WPSAMLERR013',
			'description'     => 'Unable to find a certificate matching the configured fingerprint.',
			'fix'             => 'Please copy the IDP certificate from your IDP and paste it in the X509 Certificate input field of the respective IDP in the IDP Configuration tab of the plugin.',
			'cause'           => 'Certificate Not Found',
			'test_config_msg' => 'Unable to find a certificate matching the configured fingerprint.',
		),
		'WPSAMLERR014' => array(
			'code'            => 'WPSAMLERR014',
			'description'     => 'This error occurs when an incorrect certificate is added on the Identity Provider for Encryption.',
			'fix'             => 'Please check if the certificate added in Identity Provider is the same as the certificate provided in the Service Provider Metadata tab of the Plugin.',
			'cause'           => 'Encryption Certificate Mismatch',
			'test_config_msg' => 'Incorrect certificate added on the Identity Provider for Encryption',
		),
		'WPSAMLERR015' => array(
			'code'        => 'WPSAMLERR015',
			'description' => 'This error code is shown to users when DOM extension is not installed.',
			'fix'         => 'Ask your hosting provider or internal team to install DOM extension.',
			'cause'       => 'DOM extension not found while parsing SAML Response, SAML Logout Response or SAML Metadata.',
		),
		'WPSAMLERR016' => array(
			'code'        => 'WPSAMLERR016',
			'description' => 'This error code is shown to users when the plugin detects a duplicate saml response',
			'fix'         => 'User will need to initiate the SSO again.',
			'cause'       => 'Either user have reloaded the page while plugin was processing SAMLResponse or someone has tried to send a duplicated SAMLResponse.',
		),
		'WPSAMLERR017' => array(
			'code'        => 'WPSAMLERR017',
			'description' => 'This error code is shown to users when invalid XML is passed by user or IdP.',
			'fix'         => 'Please send SAML tracer while reproducing the whole issue to samlsupport@xecurify.com.',
			'cause'       => 'Invalid XML detected by plugin in form of SAML Logout Response, SAML Response.',
		),
		'WPSAMLERR018' => array(
			'code'        => 'WPSAMLERR018',
			'description' => 'This error occurs when you have enabled the Do not auto create users if roles are not mapped here option in Role Mapping section of the attribute mapping tab.',
			'fix'         => 'Enable the option only if you want to restrict login to accounts with certain roles. You will also have to map these role values to their respective WordPress role values. If you want users with any role to login disable this toggle.',
			'cause'       => 'Not a WordPress Member.',
		),
		'WPSAMLERR019' => array(
			'code'        => 'WPSAMLERR019',
			'description' => 'This error is displayed when the user role is restricted from logging in.',
			'fix'         => 'If you think you should not be seeing this message make sure that you have configured correct role names to be restricted in the Do not allow the users to login with the following roles input box.',
			'cause'       => 'User role is restricted',
		),
		'WPSAMLERR020' => array(
			'code'        => 'WPSAMLERR020',
			'description' => 'This error is displayed when the PHP openssl extension is not installed or disabled.',
			'fix'         => 'Please ensure that the OpenSSL extension is installed and activated in order to activate the plugin.',
			'cause'       => 'PHP openssl extension is either not installed or disabled.',
		),
		'WPSAMLERR021' => array(
			'code'        => 'WPSAMLERR021',
			'description' => 'This error is displayed when the users with specific domain are restricted from logging in.',
			'fix'         => 'If you think you should not be seeing this message make sure that you have configured correct domains to be restricted in the Deny users to login with specified domains option input box in the Attribute/Role Mapping tab.',
			'cause'       => 'Permission Denied : Blacklisted user.',
		),
		'WPSAMLERR022' => array(
			'code'        => 'WPSAMLERR022',
			'description' => 'This error is displayed when the domain of the user is not specified in the domains to be allowed to login.',
			'fix'         => 'If you think you should not be seeing this message make sure that you have configured correct domains to be allowed in the Allow users to login with specified domains option input box in the Attribute/Role Mapping tab.',
			'cause'       => 'Permission Denied : Not a Whitelisted user.',
		),
		'WPSAMLERR023' => array(
			'code'        => 'WPSAMLERR023',
			'description' => 'This error is displayed when the IDP status is inactive and a user tries to log in to the site.',
			'fix'         => 'Activate the IDP status in the IDP Configuration tab by selecting Activate from the Bulk Actions dropdown and then clicking on Apply.',
			'cause'       => 'IDP not enabled.',
		),
		'WPSAMLERR024' => array(
			'code'        => 'WPSAMLERR024',
			'description' => 'This error code is shown to users when the plugin receives invalid assertion in saml response.',
			'fix'         => 'Please send SAML tracer while reproducing the whole issue to samlsupport@xecurify.com.',
			'cause'       => 'Invalid SAML Assertion',
		),
		'WPSAMLERR025' => array(
			'code'        => 'WPSAMLERR025',
			'description' => 'This error code is shown to users when the plugin is unable to process the Logout Request.',
			'fix'         => 'Please send SAML tracer while reproducing the whole issue to samlsupport@xecurify.com.',
			'cause'       => 'Invalid Logout Request',
		),
		'WPSAMLERR026' => array(
			'code'        => 'WPSAMLERR026',
			'description' => 'This error code is shown to users when the plugin is unable to process SAML Metadata.',
			'fix'         => 'Please reach out to samlsupport@xecurify.com with the metadata you are trying to import/ your IDP metadata URL.',
			'cause'       => 'Invalid Metadata file/URL',
		),
		'WPSAMLERR027' => array(
			'code'        => 'WPSAMLERR027',
			'description' => 'This error code is shown to users when the plugin is unable to decrypt encrypted elements in SAML Response.',
			'fix'         => 'Please send SAML tracer while reproducing the whole issue to samlsupport@xecurify.com.',
			'cause'       => 'Incorrect IDP certificates',
		),
		'WPSAMLERR028' => array(
			'code'        => 'WPSAMLERR028',
			'description' => 'This error code is shown to users when the plugin is unable to process XML with xmlseclibs.',
			'fix'         => 'Please send SAML tracer while reproducing the whole issue to samlsupport@xecurify.com.',
			'cause'       => 'Unable to process XML',
		),
		'WPSAMLERR029' => array(
			'code'            => 'WPSAMLERR029',
			'description'     => 'This error code is shown to users when the plugin license has expired and hence the SSO has stopped working.',
			'fix'             => 'Please renew your plugin license to get the SSO working.',
			'cause'           => 'Plugin License Expired',
			'test_config_msg' => 'This error code indicates that the plugin license has expired.',
		),
		'WPSAMLERR030' => array(
			'code'            => 'WPSAMLERR030',
			'description'     => 'This error code occurs when the same plugin license is used on multiple sites or an incorrect license key is entered.',
			'fix'             => 'Please contact your administrator to use the correct license.',
			'cause'           => 'Invalid License Found.',
			'test_config_msg' => 'This error code indicates that the plugin license is invalid.',
		),
		'WPSAMLERR031' => array(
			'code'            => 'WPSAMLERR031',
			'description'     => 'This error code indicates that there has been some issue with how you have activated your license.',
			'fix'             => 'Reach out to us at samlsupport@xecurify.com from your registered email address',
			'cause'           => 'License File missing from the plugin.',
			'test_config_msg' => 'This error code indicates that there is some issue with license activation.',
		),
		'WPSAMLERR032' => array(
			'code'        => 'WPSAMLERR032',
			'description' => 'This error is displayed when the Curl extension is not installed or disabled.',
			'fix'         => 'Please ensure that the Curl extension is installed and activated in order to activate the plugin.',
			'cause'       => 'Curl extension is either not installed or disabled.',
		),
		'WPSAMLERR033' => array(
			'code'        => 'WPSAMLERR033',
			'description' => 'This error occurred while parsing encrypted XML.',
			'fix'         => 'Either SAML Response sent by IDP is not correct. Send IdP configurations and plugin configurations to samlsupport@xecurify.com for further debugging.',
			'cause'       => 'IdP is not configured correctly or the SAML Response contains insecure elements.',
		),
		'WPSAMLERR034' => array(
			'code'        => 'WPSAMLERR034',
			'description' => 'This error code indicates that you have not configured any Identity Provider as default in the IDP Configuration tab.',
			'fix'         => 'You will need to select atleast 1 Identity Provider as default in the IDP Configuration tab.',
			'cause'       => 'No Default IDP selected',
		),
		'WPSAMLERR035' => array(
			'code'        => 'WPSAMLERR035',
			'description' => 'This error code indicates that the Password reset URL is not configured in AzureB2C configuration.',
			'fix'         => 'You will need to check the AzureB2C Policies for the Password Reset.',
			'cause'       => 'Password Reset URL not configured',
		),
		'WPSAMLERR036' => array(
			'code'        => 'WPSAMLERR036',
			'description' => 'This error code indicates that you have No Such Identity Provider is existed in your IDP Configuration.',
			'fix'         => 'You will need to re-check if the Identity Provider is present in the IDP Configuration tab.',
			'cause'       => 'No Such Identity Provider is Configured At your SP',
		),
		'WPSAMLERR037' => array(
			'code'            => 'WPSAMLERR037',
			'description'     => 'This error code indicates that you have provided a empty value to the UserName/Email.',
			'fix'             => 'Please provide a valid value to the UserName/Email attribute name in Attribute Mapping tab.',
			'cause'           => 'UserName/Email Missing or invalid',
			'test_config_msg' => 'This error code indicates that the UserName/Email attribute value is empty.',
		),
		'WPSAMLERR038' => array(
			'code'        => 'WPSAMLERR038',
			'description' => 'This error code indicates that the user roles other than administrator has accessed the Test Configuration URL.',
			'fix'         => 'Users other than administrator cannot access the Test Configuration Window. Please login to your site as Administrator and try performing the test configuration again.',
			'cause'       => 'Test Configuration not allowed for non-admin users.',
		),
		'WPSAMLERR039' => array(
			'code'        => 'WPSAMLERR039',
			'description' => 'This error is displayed when you have enabled SSO on more sites than the license purchased for.',
			'fix'         => 'Please ensure that the SSO is enabled only on the sites for which you have purchased the license or reach out to us at samlsupport@xecurify.com to upgrade your license.',
			'cause'       => 'Subsite Limit Exceeded.',
		),
	);
}
