<?php
/**
 * Widget UI Handler - Base Module
 *
 * Handles widget UI for base module - provides basic login functionality.
 *
 * @package miniorange-saml-20-single-sign-on
 * @subpackage Module\Base\Handler\UI
 */

namespace MOSAML\Module\Base\Handler\UI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;
use MOSAML\SRC\Handler\UI\Login_Page_UI_Handler;

/**
 * Mo_SAML_Login_Widget class extends WP_Widget to create a SAML login widget.
 */
class Widget_UI_Handler extends \WP_Widget {

	/**
	 * Stores Widget_UI_Handler object.
	 *
	 * @var object
	 */
	private static $instance;

	/**
	 * Constructor for the widget.
	 */
	public function __construct() {
		parent::__construct(
			'mosaml_login_widget',
			'miniOrange SAML Login',
			array( 'description' => __( 'This is a miniOrange SAML login widget.', 'miniorange-saml-20-single-sign-on' ) )
		);
	}

	/**
	 * Returns Widget_UI_Handler class object.
	 *
	 * @return Widget_UI_Handler
	 */
	public static function get_instance() {
		if ( ! isset( self::$instance ) ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Display the widget content on the frontend.
	 *
	 * @param array $args     Display arguments.
	 * @param array $instance Settings for the widget instance.
	 * @return void
	 */
	public function widget( $args, $instance ) {
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $args is already escaped by WordPress.
		echo $args['before_widget'];

		if ( ! empty( $instance['wid_title'] ) ) {
			$wid_title = apply_filters( 'mosaml_widget_title_internal', $instance['wid_title'] );
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $args is already escaped by WordPress.
			echo $args['before_title'] . esc_html( $wid_title ) . $args['after_title'];
		}

		$this->login_form();

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $args is already escaped by WordPress.
		echo $args['after_widget'];
	}

	/**
	 * Update widget settings.
	 *
	 * @param array $new_instance New settings.
	 * @param array $old_instance Old settings.
	 * @return array Updated settings.
	 */
	public function update( $new_instance, $old_instance ) {
		$instance = array();
		// phpcs:ignore WordPress.WP.AlternativeFunctions.strip_tags_strip_tags -- strip_tags is appropriate here for widget title.
		$instance['wid_title'] = ! empty( $new_instance['wid_title'] ) ? strip_tags( $new_instance['wid_title'] ) : '';
		return $instance;
	}

	/**
	 * Display the widget form in the admin.
	 *
	 * @param array $instance Current settings.
	 * @return void
	 */
	public function form( $instance ) {
		$wid_title = ! empty( $instance['wid_title'] ) ? $instance['wid_title'] : '';
		?>
		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'wid_title' ) ); ?>">
				<?php esc_html_e( 'Title:', 'miniorange-saml-20-single-sign-on' ); ?>
			</label>
			<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'wid_title' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'wid_title' ) ); ?>" type="text" value="<?php echo esc_attr( $wid_title ); ?>" />
		</p>
		<?php
	}

	/**
	 * Display the login form in the widget.
	 *
	 * @return void
	 */
	public function login_form() {
		if ( ! is_user_logged_in() ) {
			$this->display_login_links();
		} else {
			$this->display_user_greeting();
		}
	}

	/**
	 * Display login links for non-logged-in users.
	 *
	 * @return void
	 */
	protected function display_login_links() {
		$idps = DB_Utils::get_records(
			'mosaml_idp_details',
			array(
				'environment_id' => DB_Utils::get_environment_details( 'id' ),
				'status'         => 'active',
			)
		);

		if ( empty( $idps ) ) {
			echo '<p>' . esc_html__( 'Please configure the miniOrange SAML Plugin first.', 'miniorange-saml-20-single-sign-on' ) . '</p>';
			return;
		}

		foreach ( $idps as $idp ) {
			$shortcode_widget_handler = Utility::get_handler_object( 'shortcode_widget_data', true, 'admin' );
			$shortcode_widget_data    = $shortcode_widget_handler->get_data(
				array(
					'subsite_id' => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
					'idp_id'     => $idp->id,
				)
			);

			$login_text      = $this->get_login_text( $shortcode_widget_data, $idp );
			$form_id         = 'mosaml_widget_form_' . esc_attr( $idp->id );
			$redirect_to_url = rawurlencode( Utility::get_current_page_url() );
			$sso_login_url   = home_url() . '/?option=saml_user_login&idp=' . rawurlencode( $idp->idp_id ) . '&redirect_to=' . $redirect_to_url;

			$sso_button_handler = Utility::get_handler_object( 'sso_button_data', true, 'admin' );
			$sso_button_data    = $sso_button_handler->get_data(
				array(
					'idp_id'     => $idp->id,
					'subsite_id' => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
				)
			);

			$use_button_as_widget = ! empty( $sso_button_data->use_button_as_widget ) ? $sso_button_data->use_button_as_widget : ( ! empty( $sso_button_data->sso_button_config['use_button_as_widget'] ) ? $sso_button_data->sso_button_config['use_button_as_widget'] : '' );
			if ( ! empty( $use_button_as_widget ) && 'checked' === $use_button_as_widget ) {
				if ( empty( $sso_button_data->sso_button_config['button_text'] ) ) {
					$sso_button_data->sso_button_config['button_text'] = $login_text;
				}
				$allowed_html = array(
					'style' => array(
						'type' => true,
					),
					'div'   => array(
						'id'          => true,
						'class'       => true,
						'name'        => true,
						'data-idp-id' => true,
					),
					'a'     => array(
						'href'  => true,
						'style' => true,
					),
					'span'  => array(),
				);
				echo wp_kses( Login_Page_UI_Handler::generate_sso_button_html( $sso_button_data, $idp->id, $sso_login_url ), $allowed_html );
				echo '<br/>';
			} else {
				?>
				<form id="<?php echo esc_attr( $form_id ); ?>" method="post" action="">
					<input type="hidden" name="option" value="saml_user_login" />
					<input type="hidden" name="redirect_to" value="<?php echo esc_url( Utility::get_current_page_url() ); ?>" />
					<input type="hidden" name="idp" value="<?php echo esc_attr( $idp->idp_id ); ?>" />
					<a href="#" onclick="document.getElementById('<?php echo esc_attr( $form_id ); ?>').submit(); return false;"><?php echo esc_html( $login_text ); ?></a>
				</form>
				<br/>
				<?php
			}
		}
	}

	/**
	 * Get login text for widget.
	 * Base version always uses default text.
	 *
	 * @param object $shortcode_widget_data Widget data object.
	 * @param object $idp IDP object.
	 * @return string
	 */
	protected function get_login_text( $shortcode_widget_data, $idp ) {
		return 'Login with ' . $idp->idp_name;
	}

	/**
	 * Display greeting and logout link for logged-in users.
	 *
	 * @return void
	 */
	protected function display_user_greeting() {
		$user   = wp_get_current_user();
		$idp_id = get_user_meta( $user->ID, 'mo_saml_logged_in_with_idp', true );

		$shortcode_widget_handler = Utility::get_handler_object( 'shortcode_widget_data', true, 'admin' );
		$shortcode_widget_data    = $shortcode_widget_handler->get_data(
			array(
				'subsite_id' => Utility::get_subsite_id_for_environment( DB_Utils::get_environment_details( 'id', true ) ),
				'idp_id'     => $idp_id,
			)
		);

		$greeting_text   = $this->get_greeting_text( $shortcode_widget_data );
		$greeting_option = isset( $shortcode_widget_data->widget_config['greeting_name'] ) ? $shortcode_widget_data->widget_config['greeting_name'] : 'USERNAME';
		$greeting_name   = Utility::get_user_name( $user, $greeting_option );
		$logout_text     = $this->get_logout_text( $shortcode_widget_data );

		echo esc_html( $greeting_text . ' ' . $greeting_name ) . ' | <a href="' . esc_url( wp_logout_url( Utility::get_current_page_url() ) ) . '">' . esc_html( $logout_text ) . '</a>';
	}

	/**
	 * Get greeting text for widget.
	 * Base module uses default text.
	 *
	 * @param object $shortcode_widget_data Widget data object.
	 * @return string
	 */
	protected function get_greeting_text( $shortcode_widget_data ) {
		return 'Hello,';
	}

	/**
	 * Get logout text for widget.
	 * Base module uses default text.
	 *
	 * @param object $shortcode_widget_data Widget data object.
	 * @return string
	 */
	protected function get_logout_text( $shortcode_widget_data ) {
		return 'Logout';
	}
}

