<?php
/**
 * IDPs List Table Class.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/template
 */

namespace MOSAML\SRC\Template;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Utils\Feature_Control;
use WP_List_Table;
/**
 * IDPs List Table Class.
 */
class Idp_List_Table extends WP_List_Table {

	/**
	 * IDP model data.
	 *
	 * @var array
	 */
	private $idp_details = array();

	/**
	 * Constructor.
	 *
	 * @param array $idp_details_dto IDP details data transfer object.
	 */
	public function __construct( $idp_details_dto ) {
		$this->idp_details = $idp_details_dto;
		parent::__construct(
			array(
				'screen' => 'mosaml_idp_list_table',
			)
		);
		add_action( 'admin_head', array( $this, 'add_custom_screen_options_filter' ) );
	}

	/**
	 * Add custom screen options filter.
	 *
	 * @return void
	 */
	public function add_custom_screen_options_filter() {
		$screen = get_current_screen();
		add_filter( 'manage_' . $screen->id . '_columns', array( $this, 'manage_screen_options_columns' ) );
	}

	/**
	 * Manage screen options columns.
	 *
	 * @param array $columns Columns.
	 * @return array
	 */
	public function manage_screen_options_columns( $columns ) {
		return array( 'idp_id' => 'IDP ID' );
	}

	/**
	 * Get columns.
	 *
	 * @return array
	 */
	public function get_columns() {
		return array(
			'cb'        => '<input type="checkbox" />',
			'idp_name'  => 'IDP Name',
			'idp_id'    => 'IDP ID',
			'entity_id' => 'IDP Entity ID',
			'status'    => 'Status',
			'actions'   => 'Actions',
		);
	}

	/**
	 * Get sortable columns.
	 *
	 * @return array
	 */
	public function get_sortable_columns() {
		return array(
			'idp_name' => array( 'idp_name', false ),
			'status'   => array( 'status', false ),
		);
	}

	/**
	 * Column default.
	 *
	 * @param object $item        Item object.
	 * @param string $column_name Column name.
	 * @return string
	 */
	public function column_default( $item, $column_name ) {
		switch ( $column_name ) {
			case 'idp_id':
				return esc_html( $item->idp_id );
			case 'entity_id':
				return esc_html( $item->entity_id );
			default:
				return '';
		}
	}

	/**
	 * Column checkbox.
	 *
	 * @param object $item Item object.
	 * @return string
	 */
	public function column_cb( $item ) {
		ob_start();
		$disable_due_to_no_idp = Utility::disable_forms_if_no_idps_configured();
		?>
		<input type="checkbox" name="bulk_action_record[]" value="<?php echo esc_attr( $item->idp_id ); ?>" <?php echo esc_attr( $disable_due_to_no_idp ); ?>/>
		<?php
		return ob_get_clean();
	}

	/**
	 * Function to get the IDP Name column's content.
	 *
	 * @param object $item Current item object.
	 * @return String
	 */
	public function column_idp_name( $item ) {
		ob_start();
		echo esc_attr( $item->idp_name );
		if ( $item->default_idp ) :
			?>
		<div class="mosaml-default-idp-div">
			<span class="mosaml-default-idp-label">
				Default
			</span>
			<a href="https://faq.miniorange.com/knowledgebase/what-is-default-identity-provider/" target="_blank" rel="noopener noreferrer" class="mosaml-no-outline-link">
				<svg class="mosaml-default-idp-icon" width="17" height="17" x="0" y="0" viewBox="0 0 24 24" xml:space="preserve">
					<g>
						<path d="M12 22C6.486 22 2 17.514 2 12S6.486 2 12 2s10 4.486 10 10-4.486 10-10 10zm0-18c-4.411 0-8 3.589-8 8s3.589 8 8 8 8-3.589 8-8-3.589-8-8-8z" fill="#3e8fd0" opacity="1" data-original="#000000"></path>
						<path d="M12 16.75a1 1 0 0 1-1-1v-4.282a1 1 0 0 1 2 0v4.282a1 1 0 0 1-1 1zM12 9.25c-.26 0-.52-.11-.71-.29-.18-.19-.29-.45-.29-.71 0-.13.03-.26.08-.38s.12-.23.21-.33c.38-.37 1.04-.37 1.42 0 .18.19.29.45.29.71s-.11.52-.29.71c-.1.09-.21.16-.33.21-.12.06-.25.08-.38.08z" fill="#3e8fd0" opacity="1" data-original="#000000"></path>
					</g>
				</svg>
			</a>
		</div>
			<?php
		endif;
		return ob_get_clean();
	}

	/**
	 * Function to get the IDP Status column's content.
	 *
	 * @param object $item Current item object.
	 * @return String
	 */
	public function column_status( $item ) {
		ob_start();
		?>
		<span class="mosaml-status-<?php echo esc_attr( $item->status ); ?>">
			<?php echo esc_attr( Constants::IDP_STATUS[ $item->status ] ); ?>
		</span>
		<?php
		return ob_get_clean();
	}

	/**
	 * Function to get the content for the actions column.
	 *
	 * @param object $item Current item object.
	 * @return String
	 */
	public function column_actions( $item ) {
		$edit_url = add_query_arg(
			array(
				'page'   => 'mo_saml_settings',
				'tab'    => 'sp_setup',
				'action' => 'edit',
				'idp'    => $item->idp_id,
			),
			admin_url( 'admin.php' )
		);
		$test_url = Utility::get_test_config_url( $item->idp_id );

		$attr_url = add_query_arg(
			array(
				'page'   => 'mo_saml_settings',
				'tab'    => 'attribute_role_mapping',
				'subtab' => 'attribute_mapping',
				'idp'    => $item->idp_id,
			),
			admin_url( 'admin.php' )
		);
		$role_url = add_query_arg(
			array(
				'page'   => 'mo_saml_settings',
				'tab'    => 'attribute_role_mapping',
				'subtab' => 'role_mapping',
				'idp'    => $item->idp_id,
			),
			admin_url( 'admin.php' )
		);

		$relay_state = add_query_arg(
			array(
				'page'   => 'mo_saml_settings',
				'tab'    => 'sso_redirection_settings',
				'subtab' => 'settings',
				'idp'    => $item->idp_id,
			),
			admin_url( 'admin.php' )
		);

		$is_default = ! empty( $item->default_idp );

		$dropdown_id             = 'actions-dropdown-' . $item->idp_id;
		$disabled_due_to_license = Utility::mo_saml_get_disabled_attribute( ! Feature_Control::free_or_license_specific_feature_enabled() );

		ob_start();
		?>
		<div>
			<button type="button" class="button button-primary button-large" <?php echo esc_attr( $disabled_due_to_license ); ?> onclick="toggleDropdown('<?php echo esc_attr( $dropdown_id ); ?>')">
				<?php esc_html_e( 'Select an Action', 'miniorange-saml-20-single-sign-on' ); ?><span>
					<svg xmlns="http://www.w3.org/2000/svg" class="mosaml-dropdown-icon">
						<path d="M5 6l5 5 5-5 2 1-7 7-7-7 2-1z" fill="white"/>
					</svg>
				</span>
			</button>

			<div id="<?php echo esc_attr( $dropdown_id ); ?>" class="mosaml-dropdown-content">
				<a href="#" onclick="testIdpConfiguration('<?php echo esc_attr( $test_url ); ?>')" class="mosaml-idp-action-link">
					<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 385 424" fill="none" class="mosaml-idp-action-icon">
					<path d="M35.6535 251.091C31.947 251.104 28.313 250.065 25.1737 248.094C22.0344 246.124 19.5186 243.303 17.9187 239.959C16.3188 236.616 15.7004 232.887 16.1353 229.206C16.5703 225.525 18.0407 222.043 20.3759 219.165L214.284 19.3808C215.739 17.7018 217.721 16.5672 219.905 16.1633C222.09 15.7593 224.346 16.11 226.305 17.1577C228.264 18.2055 229.808 19.888 230.685 21.9291C231.561 23.9703 231.718 26.2488 231.129 28.3906L193.522 146.303C192.413 149.27 192.041 152.463 192.437 155.606C192.833 158.75 193.986 161.75 195.796 164.35C197.606 166.95 200.021 169.072 202.831 170.534C205.642 171.996 208.766 172.755 211.934 172.745H349.041C352.747 172.732 356.381 173.771 359.52 175.742C362.66 177.712 365.175 180.533 366.775 183.877C368.375 187.22 368.994 190.949 368.559 194.63C368.124 198.311 366.653 201.792 364.318 204.671L170.41 404.455C168.955 406.134 166.973 407.269 164.789 407.673C162.605 408.077 160.348 407.726 158.389 406.678C156.43 405.63 154.886 403.948 154.009 401.907C153.133 399.866 152.976 397.587 153.565 395.445L191.172 277.533C192.281 274.566 192.653 271.373 192.257 268.23C191.861 265.086 190.708 262.086 188.898 259.486C187.088 256.886 184.674 254.764 181.863 253.302C179.052 251.839 175.929 251.081 172.76 251.091H35.6535Z" stroke="#383838" stroke-width="32" stroke-linecap="round" stroke-linejoin="round"/>
					</svg>
					<span class="mosaml-idp-action-text">		
						<?php esc_html_e( 'Test Configuration', 'miniorange-saml-20-single-sign-on' ); ?>
					</span>
				</a>
				<a href="<?php echo esc_url( $edit_url ); ?>" class="mosaml-idp-action-link">
					<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 320 315" fill="none" class="mosaml-idp-action-icon">
						<path d="M52.1587 255.741C52.1587 255.741 53.3475 255.741 53.7933 255.741L97.3332 251.729C103.426 251.134 109.073 248.46 113.382 244.15L277.734 79.7983C285.461 72.0711 289.771 61.8177 289.771 50.9699C289.771 40.1221 285.461 29.8686 277.734 22.1414L267.183 11.5908C251.729 -3.86361 224.832 -3.86361 209.378 11.5908L188.425 32.5435L45.1745 175.794C40.8651 180.104 38.1903 185.75 37.7445 191.843L33.7323 235.383C33.2865 240.881 35.2183 246.231 39.0819 250.243C42.6483 253.809 47.2549 255.741 52.1587 255.741ZM238.355 21.8442C243.11 21.8442 247.865 23.6274 251.432 27.3424L261.982 37.8931C265.549 41.4595 267.48 46.0661 267.48 50.9699C267.48 55.8737 265.549 60.6289 261.982 64.0467L248.905 77.1235L212.201 40.4193L225.278 27.3424C228.844 23.776 233.6 21.8442 238.355 21.8442ZM59.8859 193.923C59.8859 193.032 60.3317 192.289 60.9261 191.694L196.301 56.1709L233.005 92.8752L97.6304 228.25C97.6304 228.25 96.1444 229.29 95.4014 229.29L56.3195 232.857L59.8859 193.775V193.923ZM319.491 303.145C319.491 309.237 314.438 314.29 308.346 314.29H11.145C5.05241 314.29 0 309.237 0 303.145C0 297.052 5.05241 292 11.145 292H308.346C314.438 292 319.491 297.052 319.491 303.145Z" fill="#383838"/>
					</svg>
					<span class="mosaml-idp-action-text">
						<?php esc_html_e( 'Edit Configuration', 'miniorange-saml-20-single-sign-on' ); ?>
					</span>
				</a>
				<a href="#" class="mosaml-idp-action-link" onclick="deleteIDP('<?php echo esc_attr( $item->idp_id ); ?>')">	
					<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 334 377" fill="none" class="mosaml-idp-action-icon">
						<path d="M276.785 119.773C277.282 111.791 283.733 105.751 291.192 106.283C298.652 106.815 304.296 113.718 303.8 121.701L295.434 255.975C293.89 280.752 292.645 300.765 289.721 316.47C286.681 332.797 281.512 346.436 270.834 357.125C260.156 367.816 247.095 372.428 231.67 374.588C216.831 376.664 198.088 376.664 174.883 376.664H159.02C135.815 376.664 117.073 376.664 102.235 374.588C86.8091 372.428 73.7485 367.816 63.0703 357.125C52.3923 346.436 47.2232 332.797 44.1836 316.47C41.2601 300.765 40.013 280.752 38.4697 255.975L30.1045 121.701C29.6072 113.718 35.2521 106.815 42.7119 106.283C50.1716 105.751 56.6217 111.791 57.1191 119.773L65.4209 253.031C67.0428 279.066 68.1993 297.18 70.7363 310.809C73.1974 324.03 76.6325 331.028 81.5674 335.969C86.5023 340.908 93.2559 344.112 105.746 345.86C118.623 347.662 135.591 347.691 159.973 347.691H173.932C198.313 347.691 215.281 347.662 228.157 345.86C240.648 344.112 247.402 340.908 252.337 335.969C257.272 331.028 260.706 324.03 263.168 310.809C265.706 297.18 266.862 279.066 268.482 253.031L276.785 119.773ZM120.491 154.604C127.927 153.809 134.558 159.617 135.302 167.578L144.321 264.154C145.065 272.114 139.64 279.215 132.204 280.011C124.769 280.807 118.138 274.998 117.395 267.036L108.375 170.46C107.632 162.5 113.056 155.4 120.491 154.604ZM198.658 167.578C199.402 159.617 206.034 153.809 213.468 154.604C220.904 155.4 226.329 162.5 225.586 170.46L216.565 267.036C215.822 274.998 209.19 280.807 201.756 280.011C194.32 279.215 188.895 272.114 189.639 264.154L198.658 167.578ZM197.479 0.000976562C201.384 -0.00172757 204.787 -0.00421015 208 0.544922C220.694 2.71427 231.679 11.1868 237.617 23.3877C239.119 26.476 240.193 29.9315 241.426 33.8975L243.442 40.3662C243.783 41.4611 243.881 41.7715 243.962 42.0156C247.124 51.3663 255.319 57.6876 264.607 57.9395C264.853 57.946 265.151 57.9473 266.235 57.9473H320.385C327.861 57.9474 333.922 64.4331 333.922 72.4336C333.922 80.4339 327.861 86.9198 320.385 86.9199H13.5371C6.06093 86.9198 0.000178883 80.4339 0 72.4336C0 64.4331 6.06082 57.9474 13.5371 57.9473H67.6875C68.7714 57.9473 69.0712 57.946 69.3154 57.9395C78.6046 57.6875 86.7993 51.3664 89.96 42.0156C90.0432 41.7699 90.1387 41.4665 90.4814 40.3662L92.4961 33.8984C93.7287 29.9326 94.8028 26.476 96.3057 23.3877C102.243 11.1865 113.229 2.71421 125.923 0.544922C129.136 -0.00418794 132.539 -0.00172753 136.445 0.000976562H197.479ZM137.273 28.9736C132.071 28.9736 130.996 29.018 130.192 29.1553C125.961 29.8784 122.298 32.7025 120.319 36.7695C119.944 37.5419 119.564 38.6197 117.919 43.9023L116.118 49.6855C115.847 50.5562 115.636 51.2345 115.421 51.8711C114.712 53.968 113.888 55.996 112.958 57.9473H220.965C220.035 55.996 219.212 53.968 218.503 51.8711L217.805 49.6826L216.003 43.9023C214.359 38.6196 213.98 37.5419 213.604 36.7695C211.625 32.7027 207.962 29.8786 203.731 29.1553C202.928 29.0179 201.852 28.9736 196.648 28.9736H137.273Z"/>
					</svg>
					<span class="mosaml-idp-action-text">
						<?php esc_html_e( 'Delete Configuration', 'miniorange-saml-20-single-sign-on' ); ?>
					</span>
				</a>
				<?php if ( $is_default || 'inactive' === $item->status ) : ?>
					<a href="#" class="mosaml-disabled">
						<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 269 370" fill="none" class="mosaml-idp-action-icon">
							<path d="M201.293 0C214.64 0 227.44 5.30182 236.877 14.7393C246.314 24.1767 251.616 36.9767 251.616 50.3232C251.616 63.6698 246.314 76.4698 236.877 85.9072C227.44 95.3447 214.64 100.646 201.293 100.646V163.709L201.304 164.294C201.407 167.211 202.27 170.055 203.812 172.541C205.353 175.027 207.517 177.064 210.084 178.453L210.603 178.723L210.707 178.774L240.565 193.872H240.564C248.903 198.04 255.921 204.441 260.835 212.364C265.769 220.321 268.386 229.496 268.391 238.858V251.616C268.391 260.514 264.856 269.047 258.564 275.339C252.273 281.631 243.739 285.165 234.842 285.165H150.955V352.264C150.955 361.528 143.445 369.038 134.181 369.038C124.916 369.038 117.406 361.528 117.406 352.264V285.165H33.5488C24.6512 285.165 16.1178 281.631 9.82617 275.339C3.53455 269.047 0 260.514 0 251.616V238.858L0.0078125 237.981C0.170501 228.924 2.77591 220.072 7.55566 212.364C12.4691 204.441 19.487 198.04 27.8252 193.872L57.6836 178.774L57.7881 178.723C60.5827 177.334 62.9345 175.193 64.5791 172.541C66.2221 169.891 67.0943 166.836 67.0977 163.719V100.646C53.7511 100.646 40.9511 95.3447 31.5137 85.9072C22.2236 76.6172 16.9411 64.0688 16.7783 50.9482L16.7744 50.3232C16.7744 36.9767 22.0762 24.1767 31.5137 14.7393C40.9511 5.30182 53.7511 0 67.0977 0H201.293ZM67.0977 33.5488C62.6488 33.5488 58.3821 35.3161 55.2363 38.4619C52.0905 41.6077 50.3232 45.8744 50.3232 50.3232L50.3281 50.7402C50.4349 55.038 52.1889 59.1372 55.2363 62.1846C58.3821 65.3304 62.6488 67.0977 67.0977 67.0977C75.9954 67.0977 84.5287 70.6322 90.8203 76.9238C97.1119 83.2154 100.646 91.7488 100.646 100.646V163.728C100.641 173.09 98.0247 182.265 93.0908 190.222C88.1773 198.145 81.1587 204.545 72.8203 208.713L72.8213 208.714L42.9629 223.812C42.9282 223.829 42.8932 223.846 42.8584 223.863C40.0638 225.252 37.712 227.393 36.0674 230.045C34.4227 232.697 33.5505 235.756 33.5488 238.877V251.616H234.842V238.877L234.831 238.292C234.728 235.375 233.865 232.531 232.323 230.045C230.679 227.393 228.327 225.252 225.532 223.863C225.497 223.846 225.462 223.829 225.428 223.812L195.569 208.714V208.713C187.231 204.545 180.213 198.145 175.3 190.222C170.366 182.265 167.749 173.09 167.744 163.728V100.646C167.744 91.7488 171.279 83.2154 177.57 76.9238C183.862 70.6322 192.395 67.0977 201.293 67.0977L201.71 67.0928C206.008 66.986 210.107 65.232 213.154 62.1846C216.3 59.0388 218.067 54.7721 218.067 50.3232C218.067 45.8744 216.3 41.6077 213.154 38.4619C210.008 35.3161 205.742 33.5488 201.293 33.5488H67.0977Z"/>
						</svg>
						<span class="mosaml-idp-action-text">
							<?php esc_html_e( 'Make Default IDP', 'miniorange-saml-20-single-sign-on' ); ?>
						</span>
					</a>
				<?php else : ?>
					<a href="#" class="mosaml-idp-action-link" onclick="makeIdpDefault('<?php echo esc_attr( $item->idp_id ); ?>')">
						<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 269 370" fill="none" class="mosaml-idp-action-icon">
							<path d="M201.293 0C214.64 0 227.44 5.30182 236.877 14.7393C246.314 24.1767 251.616 36.9767 251.616 50.3232C251.616 63.6698 246.314 76.4698 236.877 85.9072C227.44 95.3447 214.64 100.646 201.293 100.646V163.709L201.304 164.294C201.407 167.211 202.27 170.055 203.812 172.541C205.353 175.027 207.517 177.064 210.084 178.453L210.603 178.723L210.707 178.774L240.565 193.872H240.564C248.903 198.04 255.921 204.441 260.835 212.364C265.769 220.321 268.386 229.496 268.391 238.858V251.616C268.391 260.514 264.856 269.047 258.564 275.339C252.273 281.631 243.739 285.165 234.842 285.165H150.955V352.264C150.955 361.528 143.445 369.038 134.181 369.038C124.916 369.038 117.406 361.528 117.406 352.264V285.165H33.5488C24.6512 285.165 16.1178 281.631 9.82617 275.339C3.53455 269.047 0 260.514 0 251.616V238.858L0.0078125 237.981C0.170501 228.924 2.77591 220.072 7.55566 212.364C12.4691 204.441 19.487 198.04 27.8252 193.872L57.6836 178.774L57.7881 178.723C60.5827 177.334 62.9345 175.193 64.5791 172.541C66.2221 169.891 67.0943 166.836 67.0977 163.719V100.646C53.7511 100.646 40.9511 95.3447 31.5137 85.9072C22.2236 76.6172 16.9411 64.0688 16.7783 50.9482L16.7744 50.3232C16.7744 36.9767 22.0762 24.1767 31.5137 14.7393C40.9511 5.30182 53.7511 0 67.0977 0H201.293ZM67.0977 33.5488C62.6488 33.5488 58.3821 35.3161 55.2363 38.4619C52.0905 41.6077 50.3232 45.8744 50.3232 50.3232L50.3281 50.7402C50.4349 55.038 52.1889 59.1372 55.2363 62.1846C58.3821 65.3304 62.6488 67.0977 67.0977 67.0977C75.9954 67.0977 84.5287 70.6322 90.8203 76.9238C97.1119 83.2154 100.646 91.7488 100.646 100.646V163.728C100.641 173.09 98.0247 182.265 93.0908 190.222C88.1773 198.145 81.1587 204.545 72.8203 208.713L72.8213 208.714L42.9629 223.812C42.9282 223.829 42.8932 223.846 42.8584 223.863C40.0638 225.252 37.712 227.393 36.0674 230.045C34.4227 232.697 33.5505 235.756 33.5488 238.877V251.616H234.842V238.877L234.831 238.292C234.728 235.375 233.865 232.531 232.323 230.045C230.679 227.393 228.327 225.252 225.532 223.863C225.497 223.846 225.462 223.829 225.428 223.812L195.569 208.714V208.713C187.231 204.545 180.213 198.145 175.3 190.222C170.366 182.265 167.749 173.09 167.744 163.728V100.646C167.744 91.7488 171.279 83.2154 177.57 76.9238C183.862 70.6322 192.395 67.0977 201.293 67.0977L201.71 67.0928C206.008 66.986 210.107 65.232 213.154 62.1846C216.3 59.0388 218.067 54.7721 218.067 50.3232C218.067 45.8744 216.3 41.6077 213.154 38.4619C210.008 35.3161 205.742 33.5488 201.293 33.5488H67.0977Z"/>
						</svg>
						<span class="mosaml-idp-action-text">
							<?php esc_html_e( 'Make Default IDP', 'miniorange-saml-20-single-sign-on' ); ?>
						</span>
					</a>
				<?php endif; ?>
				<a href="<?php echo esc_url( $attr_url ); ?>" class="mosaml-idp-action-link">
					<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 452 452" fill="none" class="mosaml-idp-action-icon">
						<path d="M268.479 0C287.165 0.000174216 302.312 15.1476 302.312 33.833V119.167C302.312 137.852 287.165 153 268.479 153H238.312V213.25H353.833C362.806 213.25 371.412 216.814 377.757 223.159C384.102 229.504 387.667 238.11 387.667 247.083V298.5H417.792C436.477 298.5 451.625 313.648 451.625 332.333V417.667C451.625 436.352 436.477 451.5 417.792 451.5H332.458C313.773 451.5 298.625 436.352 298.625 417.667V332.333C298.625 313.648 313.773 298.5 332.458 298.5H362.667V247.083C362.667 244.74 361.736 242.493 360.079 240.837C358.423 239.181 356.176 238.25 353.833 238.25H227.252C226.78 238.304 226.299 238.333 225.812 238.333C225.326 238.333 224.845 238.304 224.373 238.25H97.833C95.4904 238.25 93.2434 239.18 91.5869 240.837C89.9304 242.493 89.0001 244.74 89 247.083V298.5H119.167C137.852 298.5 153 313.648 153 332.333V417.667C153 436.352 137.852 451.5 119.167 451.5H33.833C15.1476 451.5 0.000174205 436.352 0 417.667V332.333C0.000176277 313.648 15.1476 298.5 33.833 298.5H64V247.083C64.0001 238.11 67.5643 229.504 73.9092 223.159C80.2541 216.814 88.86 213.25 97.833 213.25H213.312V153H183.146C164.46 153 149.313 137.852 149.312 119.167V33.833C149.313 15.1476 164.46 0.000176267 183.146 0H268.479ZM33.833 323.5C28.9548 323.5 25.0002 327.455 25 332.333V417.667C25.0002 422.545 28.9547 426.5 33.833 426.5H119.167C124.045 426.5 128 422.545 128 417.667V332.333C128 327.455 124.045 323.5 119.167 323.5H77.9395C77.4671 323.554 76.9869 323.583 76.5 323.583C76.0131 323.583 75.5329 323.554 75.0605 323.5H33.833ZM332.458 323.5C327.58 323.5 323.625 327.455 323.625 332.333V417.667C323.625 422.545 327.58 426.5 332.458 426.5H417.792C422.67 426.5 426.625 422.545 426.625 417.667V332.333C426.625 327.455 422.67 323.5 417.792 323.5H376.606C376.134 323.554 375.654 323.583 375.167 323.583C374.68 323.583 374.2 323.554 373.728 323.5H332.458ZM183.146 25C178.267 25.0002 174.313 28.9548 174.312 33.833V119.167C174.313 124.045 178.267 128 183.146 128H268.479C273.358 128 277.312 124.045 277.312 119.167V33.833C277.312 28.9547 273.358 25.0002 268.479 25H183.146Z" fill="#383838"/>
					</svg>
					<span class="mosaml-idp-action-text">	
						<?php esc_html_e( 'Attribute/Role Mapping', 'miniorange-saml-20-single-sign-on' ); ?>
					</span>
				</a>
				<a href="<?php echo esc_url( $relay_state ); ?>" class="mosaml-idp-action-link">
					<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 390 392" fill="none" class="mosaml-idp-action-icon">
						<path d="M185.667 41.8594C193.951 41.8595 200.667 48.5752 200.667 56.8594C200.667 65.1434 193.951 71.8592 185.667 71.8594H57.667C50.3293 71.8594 43.292 74.7744 38.1035 79.9629C32.9151 85.1514 30 92.1888 30 99.5264V334.192C30.0001 341.53 32.9151 348.567 38.1035 353.756C43.292 358.944 50.3294 361.859 57.667 361.859H292.333C299.671 361.859 306.708 358.944 311.896 353.756C317.085 348.567 320 341.53 320 334.192V206.192C320 197.908 326.716 191.192 335 191.192C343.284 191.192 350 197.908 350 206.192V334.192C350 349.486 343.924 364.154 333.109 374.969C322.295 385.783 307.627 391.859 292.333 391.859H57.667C42.3729 391.859 27.7052 385.783 16.8906 374.969C6.07609 364.154 6.66853e-05 349.486 0 334.192V99.5264C0 84.2323 6.0761 69.5646 16.8906 58.75C27.7052 47.9354 42.3728 41.8594 57.667 41.8594H185.667ZM363.866 4.1123C369.879 -1.58591 379.373 -1.33052 385.071 4.68262C390.769 10.6958 390.514 20.1894 384.501 25.8877L222.257 179.637C216.244 185.335 206.75 185.079 201.052 179.066C195.354 173.053 195.609 163.56 201.622 157.861L363.866 4.1123Z" fill="#383838"/>
					</svg>
					<span class="mosaml-idp-action-text">
						<?php esc_html_e( 'Redirection & SSO Links', 'miniorange-saml-20-single-sign-on' ); ?>
					</span>
				</a>
			</div>
		</div>
		<?php
		return ob_get_clean();
	}

	/**
	 * Get bulk actions.
	 *
	 * @return array
	 */
	public function get_bulk_actions() {
		return Constants::IDP_BULK_ACTIONS;
	}

	/**
	 * Get the hidden columns for the current screen.
	 *
	 * @return array The hidden columns.
	 */
	public function get_hidden_columns() {
		$screen = get_current_screen();
		return get_hidden_columns( $screen );
	}

	/**
	 * Prepare items for the IDP List Table.
	 *
	 * @return void
	 */
	public function prepare_items() {
		list( $columns, $hidden, $sortable ) = $this->get_column_info();
		$hidden                              = $this->get_hidden_columns();
		$this->_column_headers               = array( $columns, $hidden, $sortable );

		$search_term = Utility::sanitize_request_data( 's' );
		if ( ! empty( $search_term ) ) {
			$this->idp_details = array_filter(
				$this->idp_details,
				function ( $item ) use ( $search_term ) {
					return stripos( $item->idp_name, $search_term ) !== false;
				}
			);
		}

		$requested_orderby = Utility::sanitize_request_data( 'orderby' );
		$orderby           = ! empty( $requested_orderby ) ? $requested_orderby : 'idp_name';
		$order             = Utility::sanitize_request_data( 'order', false, 'asc' );

		usort(
			$this->idp_details,
			function ( $a, $b ) use ( $orderby, $order, $requested_orderby ) {
				// Keep default IDP(s) at the top only for the initial (unsorted) view.
				if ( empty( $requested_orderby ) ) {
					$result = (int) $b->default_idp - (int) $a->default_idp;
					if ( 0 !== $result ) {
						return $result;
					}
				}
				if ( 'idp_name' === $orderby ) {
					$result = strcasecmp( $a->idp_name, $b->idp_name );
					return ( 'asc' === $order ) ? $result : -$result;
				}
				if ( 'status' === $orderby ) {
					$result = strcasecmp( $a->status, $b->status );
					return ( 'asc' === $order ) ? $result : -$result;
				}
				return 0;
			}
		);

		$per_page     = intval( $this->get_items_per_page( 'items_per_page', 5 ) );
		$current_page = intval( $this->get_pagenum() );
		$total_items  = is_countable( $this->idp_details ) ? count( $this->idp_details ) : 0;
		$this->items  = array_slice( $this->idp_details, ( ( $current_page - 1 ) * $per_page ), $per_page );
		$this->set_pagination_args(
			array(
				'total_items' => $total_items,
				'per_page'    => $per_page,
			)
		);
	}

	/**
	 * Display when no items found.
	 *
	 * @return void
	 */
	public function no_items() {
		$search_term = Utility::sanitize_request_data( 's' );

		if ( ! empty( $search_term ) ) {
			printf(
				'<span class="mosaml-no-items-message">%s</span>',
				esc_html(
					sprintf(
						__( 'No such IDP is configrured. Try a different search.', 'miniorange-saml-20-single-sign-on' ),
						$search_term
					)
				)
			);
			return;
		}

		?>
		<span class="mosaml-no-items-message">
			You have not configured any IDP yet. Click on <b>Add New IDP</b> or <b>Upload Metadata</b> button to configure your IDP.
		</span>
		<?php
	}

	/**
	 * Display search box.
	 *
	 * @param string $text     The 'submit' button label.
	 * @param string $input_id ID attribute value for the search input field.
	 */
	public function search_box( $text, $input_id ) {
		if ( empty( Utility::sanitize_request_data( 's' ) ) && ! $this->has_items() ) {
			return;
		}

		$input_id = $input_id . '-search-input';

		if ( ! empty( Utility::sanitize_request_data( 'orderby' ) ) ) {
			echo '<input type="hidden" name="orderby" value="' . esc_attr( Utility::sanitize_request_data( 'orderby' ) ) . '" />';
		}
		if ( ! empty( Utility::sanitize_request_data( 'order' ) ) ) {
			echo '<input type="hidden" name="order" value="' . esc_attr( Utility::sanitize_request_data( 'order' ) ) . '" />';
		}
		if ( ! empty( Utility::sanitize_request_data( 'post_mime_type' ) ) ) {
			echo '<input type="hidden" name="post_mime_type" value="' . esc_attr( Utility::sanitize_request_data( 'post_mime_type' ) ) . '" />';
		}
		if ( ! empty( Utility::sanitize_request_data( 'detached' ) ) ) {
			echo '<input type="hidden" name="detached" value="' . esc_attr( Utility::sanitize_request_data( 'detached' ) ) . '" />';
		}

		$button_attributes = array(
			'id' => 'search-submit',
		);

		$is_disabled = ! defined( 'MOSAML_VERSION' ) || 4 !== MOSAML_VERSION || Utility::disable_forms_if_no_idps_configured_bool();
		if ( $is_disabled ) {
			$button_attributes = array_merge(
				$button_attributes,
				array( 'disabled' => true ),
			);
		}

		?>
		<p class="search-box">
			<label class="screen-reader-text" for="<?php echo esc_attr( $input_id ); ?>"><?php echo esc_html( $text ); ?>:</label>
			<input type="search" id="<?php echo esc_attr( $input_id ); ?>" name="s" value="<?php _admin_search_query(); ?>" placeholder="Search your Identity Provider" <?php echo $is_disabled ? 'disabled' : ''; ?>/>
			<?php

			submit_button(
				$text,
				'primary button-large',
				'',
				false,
				$button_attributes,
			);
			?>
		</p>
		<?php
	}
}
