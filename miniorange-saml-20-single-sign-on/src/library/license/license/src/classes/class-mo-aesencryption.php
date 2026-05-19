<?php
/**
 * This file is part of miniOrange WP plugin.
 *
 * @package    miniOrange
 * @author     miniOrange Security Software Pvt. Ltd.
 */

namespace MOSAML\LicenseLibrary\Classes;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class AESEncryption is used for encrypting or decrypting data.
 */
class Mo_AESEncryption {

	/**
	 * Encrpyts the data passed to the function using AES-128-ECB method
	 * and returns the encrypted value.
	 *
	 * @param string $data The data to be encrypted.
	 * @param string $key The encryption key.
	 *
	 * @return string
	 */
	public static function encrypt_data( $data, $key ) {
		$key       = openssl_digest( $key, 'sha256' );
		$method    = 'aes-128-ecb';
		$str_crypt = openssl_encrypt( $data, $method, $key, OPENSSL_RAW_DATA || OPENSSL_ZERO_PADDING );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Used to safely store encrypted binary data as text.
		return base64_encode( $str_crypt );
	}

	/**
	 * Decrpyts the data passed to the function which was encrypted using
	 * AES-128-ECB method and returns the decrypted value.
	 *
	 * @param string $data The data to be decrypted.
	 * @param string $key The decryption key.
	 *
	 * @return string
	 */
	public static function decrypt_data( $data, $key ) {
		if ( null === $data || '' === $data ) {
			return '';
		}
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Used to decode encrypted data stored as base64.
		$str_in = base64_decode( $data, true );
		if ( false === $str_in ) {
			return '';
		}
		$key     = openssl_digest( $key ?? '', 'sha256' );
		$method  = 'AES-128-ECB';
		$iv_size = openssl_cipher_iv_length( $method );
		$iv      = substr( $str_in, 0, $iv_size );
		$data    = substr( $str_in, $iv_size );
		$clear   = openssl_decrypt( $data, $method, $key, OPENSSL_RAW_DATA || OPENSSL_ZERO_PADDING, $iv );

		return $clear;
	}
}