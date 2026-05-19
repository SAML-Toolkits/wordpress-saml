<?php
/**
 * Login Page UI Handler.
 *
 * @package miniorange-saml-20-single-sign-on
 */

namespace MOSAML\SRC\Handler\UI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Traits\Instance;
use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Constant\Plugin_Files_Constants;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Feature_Control;

/**
 * Handles rendering and assets for the WordPress login page SSO Button UI.
 */
class Login_Page_UI_Handler {
	use Instance;

	/**
	 * Whether the current wp-login request is using the configured backdoor URL (enterprise).
	 *
	 * @var bool
	 */
	private static $is_backdoor_login = false;

	/**
	 * Whether the login page request is the SAML backdoor URL flow.
	 *
	 * @return bool
	 */
	public static function is_backdoor_login() {
		return self::$is_backdoor_login;
	}

	/**
	 * Enqueue login page scripts and pass base data to JS.
	 *
	 * @return void
	 */
	public static function enqueue_login_scripts() {
		if ( ! wp_script_is( 'mosaml-login-js', 'enqueued' ) ) {
			wp_enqueue_script(
				'mosaml-login-js',
				plugins_url( 'static/js/login.js', MOSAML_PLUGIN_FILE ),
				array( 'jquery' ),
				Constants::VERSION_NUMBER[ MOSAML_VERSION ],
				true
			);
			wp_localize_script(
				'mosaml-login-js',
				'moSamlLoginData',
				array()
			);
		}
		wp_enqueue_style(
			'mosaml-login-css',
			plugins_url( 'static/css/login.css', MOSAML_PLUGIN_FILE ),
			array(),
			Constants::VERSION_NUMBER[ MOSAML_VERSION ]
		);
	}

	/**
	 * Add SSO button to the login page.
	 *
	 * @return void
	 */
	public static function mo_saml_add_login_links() {
		if ( 1 !== MOSAML_VERSION && ! Feature_Control::check_is_license_verified() ) {
			return;
		}

		self::enqueue_login_scripts();

		$is_enterprise = ( 4 === MOSAML_VERSION );
		if ( $is_enterprise ) {
			if ( Utility::is_legacy_data_fallback_required() ) {
				$default_idp = apply_filters(
					'mosaml_legacy_data_fallback_object',
					Utility::get_handler_object( 'sp_setup_data', true, 'admin' ),
					array(
						'environment_id' => DB_Utils::get_environment_details( 'id' ),
						'default_idp'    => true,
						'status'         => 'active',
					)
				);
				$configured_idps = $default_idp ? array( $default_idp ) : array();
			} else {
				$configured_idps = DB_Utils::get_records(
					Constants::DATABASE_TABLE_NAMES['idp_details'],
					array(
						'environment_id' => DB_Utils::get_environment_details( 'id' ),
						'status'         => 'active',
					)
				);
			}
		} else {
			if ( Utility::is_legacy_data_fallback_required() ) {
				$default_idp = apply_filters(
					'mosaml_legacy_data_fallback_object',
					Utility::get_handler_object( 'sp_setup_data', true, 'admin' ),
					array(
						'environment_id' => DB_Utils::get_environment_details( 'id' ),
						'default_idp'    => true,
						'status'         => 'active',
					)
				);
			} else {
				$default_idp = Utility::get_default_idp();
			}
			$configured_idps = $default_idp ? array( $default_idp ) : array();
		}
		$configured_idps = ! empty( $configured_idps ) ? $configured_idps : array();

		if ( Utility::is_legacy_data_fallback_required() ) {
			$hide_wp_login_object = apply_filters(
				'mosaml_legacy_data_fallback_object',
				Utility::get_handler_object( 'hide_wp_login_data', true, 'admin' ),
				array(
					'idp_id'     => DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id' ) ),
					'subsite_id' => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
				)
			);
		} else {
			$hide_wp_login_object = Utility::get_handler_object( 'hide_wp_login_data', true, 'admin' )->get_data(
				array(
					'idp_id'     => DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id' ) ),
					'subsite_id' => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
				)
			);
		}

		foreach ( $configured_idps as $idp_details ) {
			$idp_lookup_id = $idp_details->id;
			if ( Utility::is_legacy_data_fallback_required() && ! empty( $idp_details->idp_id ) ) {
				$idp_lookup_id = $idp_details->idp_id;
			}
			$button_config = self::get_button_configuration( $idp_lookup_id );
			if ( false === $button_config || 'checked' !== $button_config['sso_button_data']->enable_sso_button ) {
				continue;
			}

			$sso_button_data = $button_config['sso_button_data'];
			$button_styles   = $button_config['button_styles'];
			$class_name      = $button_config['class_name'];
			$idp_identifier  = $button_config['idp_identifier'];
			$button_text     = $button_config['button_text'];

			$button_styles_css = self::generate_button_css( $button_styles, $class_name, $idp_identifier, false );

			$idp_id       = $sso_button_data->sso_button_config['idp_id'];
			$position     = $sso_button_data->sso_button_config['button_position'];
			$is_below     = 'below' === $position;
			$sp_endpoints = Utility::get_handler_object( 'sp_endpoints_data', true, 'admin' )->get_data(
				array(
					'environment_id' => DB_Utils::get_environment_details( 'id' ),
				)
			);
			if ( ! empty( $sp_endpoints ) ) {
				$sp_base_url = $sp_endpoints->sp_base_url;
			} else {
				$sp_base_url = home_url();
			}

			ob_start();
			require Plugin_Files_Constants::TEMPLATE_LOGIN_BUTTON_HTML;
			$button_html = ob_get_clean();

			/**
			 * Filter hook to add custom CSS or modify the SSO button HTML.
			 *
			 * @param string $html The SSO button HTML including styles.
			 * @return string Modified HTML with custom CSS or styling.
			 */
			$button_html = apply_filters( 'mosaml_add_custom_css_in_sso_button_internal', $button_html, $idp_id );

			// Capture template output to apply filter.
			$is_backdoor_login = self::is_backdoor_login();
			ob_start();
			require Plugin_Files_Constants::TEMPLATE_LOGIN_PAGE_SSO_BUTTON;
			$button_html = ob_get_clean();

			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Filter output is expected to contain HTML/CSS
			echo $button_html;
		}
	}

	/**
	 * Get and prepare SSO button configuration.
	 * Common function to retrieve button settings and prepare them for use.
	 *
	 * @param int $idp_db_id IDP database ID.
	 * @return array|false Array with button configuration data or false if button is not enabled.
	 */
	private static function get_button_configuration( $idp_db_id ) {
		$sso_button_handler = Utility::get_handler_object( 'sso_button_data', true, 'admin' );
		$sso_button_data    = $sso_button_handler->get_data(
			array(
				'subsite_id' => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
				'idp_id'     => $idp_db_id,
			)
		);


		if ( ! isset( $sso_button_data->sso_button_config['idp_id'] ) ) {
			if ( Utility::is_legacy_data_fallback_required() ) {
				$default_idp = apply_filters(
					'mosaml_legacy_data_fallback_object',
					Utility::get_handler_object( 'sp_setup_data', true, 'admin' ),
					array(
						'environment_id' => DB_Utils::get_environment_details( 'id' ),
						'default_idp'    => true,
						'status'         => 'active',
					)
				);
			} else {
				$default_idp = Utility::get_default_idp();
			}
			$sso_button_data->sso_button_config['idp_id'] = $default_idp->idp_id;
		}

		$button_styles  = $sso_button_data->sso_button_config;
		$class_name     = 'mo-saml-login-sso-button_' . $idp_db_id;
		$idp_identifier = ! empty( $button_styles['idp_id'] ) ? $button_styles['idp_id'] : $idp_db_id;
		$button_text    = ! empty( $button_styles['button_text'] ) ? $button_styles['button_text'] : 'Login with ' . ( isset( $default_idp->idp_name ) ? $default_idp->idp_name : '' );
		$position       = ! empty( $button_styles['button_position'] ) ? $button_styles['button_position'] : 'above';

		return array(
			'sso_button_data' => $sso_button_data,
			'button_styles'   => $button_styles,
			'class_name'      => $class_name,
			'idp_identifier'  => $idp_identifier,
			'button_text'     => $button_text,
			'position'        => $position,
		);
	}

	/**
	 * Generate CSS for SSO button based on configuration.
	 * This method extracts the CSS generation logic from mo_saml_add_login_links() for reuse.
	 *
	 * @param array  $button_styles Button style configuration array.
	 * @param string $class_name CSS class name for the button.
	 * @param string $idp_id IDP identifier for CSS selectors.
	 * @param bool   $include_span_selector Whether to include IDP-specific span font-size selector.
	 * @return string Generated CSS string.
	 */
	private static function generate_button_css( $button_styles, $class_name, $idp_id, $include_span_selector = true ) {
		$button_declarations = '';
		$button_css          = '';
		$span_font_size      = '';
		if ( is_array( $button_styles ) ) {
			if ( ! empty( $button_styles['button_color'] ) ) {
				$button_color         = Utility::mo_saml_color_hash_prefix( $button_styles['button_color'] );
				$button_declarations .= 'background-color: ' . esc_attr( $button_color ) . ' !important;';
				$button_declarations .= 'border-color: ' . esc_attr( $button_color ) . ' !important;';
			}

			if ( ! empty( $button_styles['font_color'] ) ) {
				$font_color           = Utility::mo_saml_color_hash_prefix( $button_styles['font_color'] );
				$button_declarations .= 'color: ' . esc_attr( $font_color ) . ' !important;';
			}

			if ( ! empty( $button_styles['font_size'] ) ) {
				$span_font_size       = esc_attr( $button_styles['font_size'] );
				$button_declarations .= 'font-size: ' . $span_font_size . 'px !important;';
			}

			if ( ! empty( $button_styles['button_type'] ) ) {
				switch ( $button_styles['button_type'] ) {
					case 'longbutton':
						if ( ! empty( $button_styles['button_width'] ) ) {
							$button_declarations .= 'width: ' . esc_attr( $button_styles['button_width'] ) . 'px !important;';
						}
						if ( ! empty( $button_styles['button_height'] ) ) {
							$button_declarations .= 'height: ' . esc_attr( $button_styles['button_height'] ) . 'px !important;';
						}
						if ( ! empty( $button_styles['button_curve'] ) ) {
							$button_declarations .= 'border-radius: ' . esc_attr( $button_styles['button_curve'] ) . 'px !important;';
						}
						break;
					case 'circle':
						if ( ! empty( $button_styles['button_size'] ) ) {
							$button_declarations .= 'width: ' . esc_attr( $button_styles['button_size'] ) . 'px !important;';
							$button_declarations .= 'height: ' . esc_attr( $button_styles['button_size'] ) . 'px !important;';
							$button_declarations .= 'border-radius: 50% !important;';
						}
						break;
					case 'oval':
						if ( ! empty( $button_styles['button_size'] ) ) {
							$button_declarations .= 'width: ' . esc_attr( $button_styles['button_size'] ) . 'px !important;';
							$button_declarations .= 'height: ' . esc_attr( $button_styles['button_size'] ) . 'px !important;';
							$button_declarations .= 'border-radius: 5px !important;';
						}
						break;
					case 'square':
						if ( ! empty( $button_styles['button_size'] ) ) {
							$button_declarations .= 'width: ' . esc_attr( $button_styles['button_size'] ) . 'px !important;';
							$button_declarations .= 'height: ' . esc_attr( $button_styles['button_size'] ) . 'px !important;';
							$button_declarations .= 'border-radius: 0px !important;';
						}
						break;
				}
			}
			$button_declarations .= 'align-content: space-around;';
		}

		if ( '' === $button_declarations ) {
			return '';
		}

		$button_selector = '#mo_saml_login_sso_button_' . $idp_id . '.' . $class_name;
		$button_css      = $button_selector . ' {' . $button_declarations . '}';

		if ( $include_span_selector && '' !== $span_font_size ) {
			$button_css .= $button_selector . ' span { font-size: ' . $span_font_size . 'px !important; }';
		}

		return $button_css;
	}

	/**
	 * Generate SSO button HTML for shortcode/widget use.
	 * Reuses the exact same button rendering system as login page.
	 *
	 * @param object $sso_button_data SSO button data object.
	 * @param int    $idp_db_id IDP database ID (for class name).
	 * @param string $sso_login_url SSO login URL.
	 * @return string Button HTML with CSS.
	 */
	public static function generate_sso_button_html( $sso_button_data, $idp_db_id, $sso_login_url ) {
		self::enqueue_login_scripts();

		$button_config = self::get_button_configuration( $idp_db_id );
		if ( false === $button_config ) {
			return '';
		}

		$button_styles  = $button_config['button_styles'];
		$class_name     = $button_config['class_name'];
		$idp_identifier = $button_config['idp_identifier'];
		$button_text    = $button_config['button_text'];

		$button_styles_css = self::generate_button_css( $button_styles, $class_name, $idp_identifier );

		$html = '';
		if ( ! empty( $button_styles_css ) ) {
			$html .= '<style type="text/css">' . $button_styles_css . '</style>';
		}

		$html .= '<div id="mo_saml_button_' . esc_attr( $idp_identifier ) . '" name="mo_saml_button" class="mo-saml-login-button-container" data-idp-id="' . esc_attr( $idp_identifier ) . '">';
		$html .= '<a href="' . esc_url( $sso_login_url ) . '" style="text-decoration:none;display:block;">';
		$html .= '<div id="mo_saml_login_sso_button_' . esc_attr( $idp_identifier ) . '" class="mo-saml-login-sso-button ' . esc_attr( $class_name ) . '">';
		$html .= '<span>' . esc_html( $button_text ) . '</span>';
		$html .= '</div>';
		$html .= '</a>';
		$html .= '</div>';

		/**
		 * Filter hook to add custom CSS or modify the SSO button HTML.
		 *
		 * @param string $html The SSO button HTML including styles.
		 * @return string Modified HTML with custom CSS or styling.
		 */
		$html = apply_filters( 'mosaml_add_custom_css_in_sso_button_internal', $html, $idp_db_id );
		return $html;
	}

	/**
	 * Modify login form to include backdoor URL if enabled.
	 *
	 * @return void
	 */
	public static function mo_saml_modify_login_form() {
		self::$is_backdoor_login = false;

		if ( 1 !== MOSAML_VERSION && ! Feature_Control::check_is_license_verified() ) {
			return;
		}

		$redirection_handler = Utility::get_handler_object( 'login_page_auto_redirection', true, 'core' );
		if ( Utility::is_legacy_data_fallback_required() ) {
			$redirection_handler = apply_filters(
				'mosaml_legacy_data_fallback_object',
				$redirection_handler,
				array(
					'option_name' => 'enable_backdoor_url_login',
					'subsite_id'  => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
					'idp_id'      => DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id' ) ),
				)
			);
		} else {
			$record = DB_Utils::get_records(
				$redirection_handler->get_table_name(),
				array(
					'option_name' => 'enable_backdoor_url_login',
					'subsite_id'  => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
					'idp_id'      => DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id' ) ),
				),
				true
			);
			if ( $record ) {
				$redirection_handler->enable_backdoor_url_login = $record->option_value;
			}
		}
		if ( 'checked' === $redirection_handler->enable_backdoor_url_login ) {
			if ( ! Utility::is_legacy_data_fallback_required() ) {
				$record = DB_Utils::get_records(
					$redirection_handler->get_table_name(),
					array(
						'option_name' => 'backdoor_url',
						'subsite_id'  => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
						'idp_id'      => DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id' ) ),
					),
					true
				);
				if ( $record ) {
					$redirection_handler->backdoor_url = $record->option_value;
				}
			}
			if ( Utility::sanitize_request_data( 'saml_sso' ) === $redirection_handler->backdoor_url ) {
				self::$is_backdoor_login = true;
				echo '<input type="hidden" name="saml_sso" value="' . esc_attr( $redirection_handler->backdoor_url ) . '">';
				return;
			}
		}
		self::hide_login_form();
	}

	/**
	 * Hide the WordPress login form.
	 *
	 * @return void
	 */
	private static function hide_login_form() {
		if ( 4 !== MOSAML_VERSION || ! Feature_Control::check_is_license_verified() ) {
			return;
		}

		if ( Utility::is_legacy_data_fallback_required() ) {
			$hide_wp_login_object = apply_filters(
				'mosaml_legacy_data_fallback_object',
				Utility::get_handler_object( 'hide_wp_login_data', true, 'admin' ),
				array(
					'idp_id'     => DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id' ) ),
					'subsite_id' => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
				)
			);
		} else {
			$hide_wp_login_object = Utility::get_handler_object( 'hide_wp_login_data', true, 'admin' )->get_data(
				array(
					'idp_id'     => DB_Utils::get_default_inserted_idp_details( 'id', DB_Utils::get_environment_details( 'id' ) ),
					'subsite_id' => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
				)
			);
		}

		if ( 'checked' === $hide_wp_login_object->hide_wp_login ) {
			wp_enqueue_script(
				'hide-wp-login-form',
				plugins_url( 'static/js/hide-wp-login-form.js', MOSAML_PLUGIN_FILE ),
				array( 'jquery' ),
				Constants::VERSION_NUMBER[ MOSAML_VERSION ],
				true
			);
		}
	}
}
