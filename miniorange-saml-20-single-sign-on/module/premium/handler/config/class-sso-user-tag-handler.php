<?php
/**
 * SSO User Tag Handler - Premium Module
 *
 * Handles SSO user tag configuration for the premium module.
 *
 * @package MOSAML\Module\Premium\Handler\Config
 */

namespace MOSAML\Module\Premium\Handler\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\Module\Standard\Handler\Config\SSO_User_Tag_Handler as Standard_SSO_User_Tag_Handler;
use MOSAML\SRC\Utils\Utility;

/**
 * SSO User Tag Handler.
 */
class SSO_User_Tag_Handler extends Standard_SSO_User_Tag_Handler {

	/**
	 * User meta key for SSO user type.
	 *
	 * @var string
	 */
	const KEY_USER_TYPE = 'mosaml_user_type';

	/**
	 * User meta value for SSO user.
	 *
	 * @var string
	 */
	const VALUE_SSO_USER = 'sso_user';

	/**
	 * SSO user filter constant.
	 *
	 * @var string
	 */
	const SSO_USER_FILTER = 'mo_saml_sso_user';

	/**
	 * Display SSO user tag.
	 *
	 * @return void
	 */
	public function display_sso_user_tag() {
		if ( 'checked' === $this->sso_user_tag_data->sso_show_user ) {
			add_filter( 'manage_users_columns', array( $this, 'add_sso_user_column' ), 1, 1 );
			add_filter( 'manage_users_custom_column', array( $this, 'display_sso_user_column_content' ), 1, 3 );
			add_filter( 'pre_get_users', array( $this, 'filter_sso_user_table' ), 99, 1 );
			add_action( 'manage_users_extra_tablenav', array( $this, 'render_filter_sso_user_actions' ), 99, 1 );
		}
	}

	/**
	 * Add SSO user column to users list table.
	 *
	 * @param array $columns Existing columns.
	 * @return array Modified columns.
	 */
	public function add_sso_user_column( $columns ) {
		$columns['ssouser'] = 'User Type';
		return $columns;
	}

	/**
	 * Display SSO user status in the users list table.
	 *
	 * @param string $value The current column value.
	 * @param string $column_name The column name.
	 * @param int    $user_id The user ID.
	 * @return string The modified column value.
	 */
	public function display_sso_user_column_content( $value, $column_name, $user_id ) {
		switch ( $column_name ) {
			case 'ssouser':
				return get_user_meta( $user_id, self::KEY_USER_TYPE, true ) ? '<div>SSO User</div>' : '';
			default:
				return $value;
		}
	}

	/**
	 * Filter users by SSO status.
	 *
	 * @param \WP_User_Query $query The user query object.
	 * @return \WP_User_Query Modified query object.
	 */
	public function filter_sso_user_table( $query ) {
		if ( ! is_admin() ) {
			return $query;
		}

		global $pagenow;

		if ( 'users.php' === $pagenow ) {
			$meta_query = array();
			switch ( Utility::sanitize_get_data( self::SSO_USER_FILTER ) ) {
				case 'sso-users':
					$meta_query = array(
						array(
							'key'     => self::KEY_USER_TYPE,
							'value'   => self::VALUE_SSO_USER,
							'compare' => '=',
						),
					);
					break;
				case 'non-sso-users':
					$meta_query = array(
						array(
							'key'     => self::KEY_USER_TYPE,
							'compare' => 'NOT EXISTS',
						),
					);
					break;
			}
			$query->set( 'meta_query', $meta_query );
		}
		return $query;
	}

	/**
	 * Render filter dropdown for SSO users.
	 *
	 * @param string $which The position of the filter (top or bottom).
	 * @return void
	 */
	public function render_filter_sso_user_actions( $which ) {
		$select_name = 'bottom' === $which ? 'mo_saml_sso_user_bottom' : self::SSO_USER_FILTER;

		echo '<select onchange="idpFilterActionsChange(this.name)" id="' . esc_attr( $select_name ) . '" name="' . esc_attr( $select_name ) . '">
				<option value="">Filter User Type</option>
				<option value="sso-users" '
			.
			( 'sso-users' === Utility::sanitize_get_data( self::SSO_USER_FILTER ) ? 'selected' : '' ) . '>SSO Users</option>
				<option value="non-sso-users" ' .
			( 'non-sso-users' === Utility::sanitize_get_data( self::SSO_USER_FILTER ) ? 'selected' : '' ) . '>Non-SSO Users</option>
			</select>

			<input type="submit" class="button action" value="Filter">';

		echo '<script>
				function idpFilterActionsChange(name) {
					if(name == "mo_saml_sso_user") {
						dropdown1 = document.getElementById("mo_saml_sso_user");
						value1 = dropdown1.value;
						dropdown2 = document.getElementById("mo_saml_sso_user_bottom");
						dropdown2.value = value1;
					}
					else if(name == "mo_saml_sso_user_bottom") {
						dropdown2 = document.getElementById("mo_saml_sso_user_bottom");
						value2 = dropdown2.value;
						dropdown1 = document.getElementById("mo_saml_sso_user");
						dropdown1.value = value2;
					}
				}
			</script>';
	}
}
