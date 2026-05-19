<?php
/**
 * This file is part of miniOrange WP plugin.
 *
 * @package    miniOrange
 * @author     miniOrange Security Software Pvt. Ltd.
 * @license    GNU/GPLv3
 * @copyright  Copyright 2015 miniOrange. All Rights Reserved.
 */

namespace MOSAML\LicenseLibrary\Classes;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Provides remote endpoints used by the license framework.
 */
class Mo_License_URL {

	const HOSTNAME = 'https://login.xecurify.com';

	const ACCOUNT_VERIFICATION_URL = self::HOSTNAME . '/moas/portal/rest/customer/key';
	const LICENSE_VERIFICATION_URL = self::HOSTNAME . '/moas/portal/api/backupcode/verify';
	const LICENSE_DOMAIN_CHECK_URL = self::HOSTNAME . '/moas/portal/api/backupcode/check';
	const LICENSE_SYNC_URL         = self::HOSTNAME . '/moas/portal/rest/customer/license';
	const REMOVE_ACCOUNT_URL       = self::HOSTNAME . '/moas/portal/api/backupcode/updatestatus';
	const ADDON_FETCH_URL          = self::HOSTNAME . '/moas/portal/api/rest/addon/list';
	const PLUGIN_DOWNLOAD_URL      = self::HOSTNAME . '/moas/plugin/download-update';
	const PLUGIN_METADATA_URL      = self::HOSTNAME . '/moas/api/plugin/metadata';
}
