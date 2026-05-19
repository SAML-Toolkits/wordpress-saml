<?php
/**
 * URL constants for the plugin.
 *
 * Contains only URLs used by the plugin.
 * (excluding the license folder, which maintains its own URL constants).
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\SRC\Constant;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * URL_Constants class.
 */
class URL_Constants {

	const HOSTNAME = 'https://login.xecurify.com';

	const PORTAL_HOSTNAME = 'https://portal.miniorange.com';

	/**
	 * Customer add endpoint.
	 *
	 * @var string
	 */
	const CUSTOMER_ADD_URL = self::HOSTNAME . '/moas/rest/customer/add';

	/**
	 * Customer key endpoint.
	 *
	 * @var string
	 */
	const CUSTOMER_KEY_URL = self::HOSTNAME . '/moas/rest/customer/key';

	/**
	 * Customer check-if-exists endpoint.
	 *
	 * @var string
	 */
	const CUSTOMER_CHECK_EXISTS_URL = self::HOSTNAME . '/moas/rest/customer/check-if-exists';

	/**
	 * Mobile get-timestamp endpoint.
	 *
	 * @var string
	 */
	const MOBILE_GET_TIMESTAMP_URL = self::HOSTNAME . '/moas/rest/mobile/get-timestamp';

	/**
	 * Notify send endpoint.
	 *
	 * @var string
	 */
	const NOTIFY_SEND_URL = self::HOSTNAME . '/moas/api/notify/send';

	/**
	 * Customer contact-us endpoint.
	 *
	 * @var string
	 */
	const CUSTOMER_CONTACT_US_URL = self::HOSTNAME . '/moas/rest/customer/contact-us';

	const PORTAL_VIEW_LICENSE_URL = self::PORTAL_HOSTNAME . '/viewlicense';

	const PORTAL_FORGOT_PASSWORD_URL = self::PORTAL_HOSTNAME . '/forgotpassword';
}
