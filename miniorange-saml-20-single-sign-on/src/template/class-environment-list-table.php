<?php
/**
 * Environment List Table Class.
 *
 * @package    MOSAML
 * @subpackage MOSAML/src/template
 */

namespace MOSAML\SRC\Template;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;
use MOSAML\SRC\Utils\DB_Utils;
use MOSAML\SRC\Utils\Utility;
use WP_List_Table;

/**
 * Environment List Table Class.
 */
class Environment_List_Table extends WP_List_Table {

	/**
	 * Environment details.
	 *
	 * @var array
	 */
	private $environment_details = array();

	/**
	 * Current environment ID.
	 *
	 * @var object
	 */
	private $current_environment_details;

	/**
	 * Disable multiple environment option.
	 *
	 * @var string
	 */
	private $disable_multiple_environment_option;

	/**
	 * Constructor.
	 *
	 * @param array  $environment_details Environment details.
	 * @param object $current_environment_details Current environment details.
	 * @param string $disable_multiple_environment_option Disable multiple environment option.
	 */
	public function __construct( $environment_details, $current_environment_details, $disable_multiple_environment_option ) {
		$this->environment_details                 = is_array( $environment_details ) ? $environment_details : array();
		$this->current_environment_details         = $current_environment_details;
		$this->disable_multiple_environment_option = $disable_multiple_environment_option;
		parent::__construct(
			array(
				'screen' => 'mosaml_environment_list_table',
			)
		);
	}

	/**
	 * Get columns.
	 *
	 * @return array
	 */
	public function get_columns() {
		return array(
			'environment_id'   => 'Environment ID',
			'environment_name' => 'Environment Name',
			'environment_url'  => 'Environment URL',
			'actions'          => 'Actions',
		);
	}

	/**
	 * Get sortable columns.
	 *
	 * @return array
	 */
	public function get_sortable_columns() {
		return array(
			'environment_name' => array( 'environment_name', false ),
		);
	}

	/**
	 * Get the hidden columns for the current screen.
	 *
	 * @return array The hidden columns.
	 */
	public function get_hidden_columns() {
		return array( 'environment_id' );
	}

	/**
	 * Prepare items for the Environment List Table.
	 *
	 * @return void
	 */
	public function prepare_items() {
		list( $columns, $hidden, $sortable ) = $this->get_column_info();
		$hidden                              = $this->get_hidden_columns();
		$this->_column_headers               = array( $columns, $hidden, $sortable );

		$search_term = Utility::sanitize_request_data( 's' );
		if ( ! empty( $search_term ) ) {
			$this->environment_details = array_filter(
				$this->environment_details,
				function ( $item ) use ( $search_term ) {
					return stripos( $item->environment_name, $search_term ) !== false;
				}
			);
		}

		$orderby                = Utility::sanitize_request_data( 'orderby', false, 'environment_name' );
		$order                  = Utility::sanitize_request_data( 'order', false, 'asc' );
		$current_environment_id = isset( $this->current_environment_details->id ) ? $this->current_environment_details->id : null;

		usort(
			$this->environment_details,
			function ( $a, $b ) use ( $orderby, $order, $current_environment_id ) {
				if ( null !== $current_environment_id ) {
					if ( $a->id === $current_environment_id && $b->id !== $current_environment_id ) {
						return -1;
					}
					if ( $b->id === $current_environment_id && $a->id !== $current_environment_id ) {
						return 1;
					}
				}

				if ( 'environment_name' === $orderby ) {
					$result = strcasecmp( $a->environment_name, $b->environment_name );
					return ( 'asc' === $order ) ? $result : -$result;
				}
				return 0;
			}
		);

		$per_page     = intval( $this->get_items_per_page( 'items_per_page', 5 ) );
		$current_page = intval( $this->get_pagenum() );
		$total_items  = is_countable( $this->environment_details ) ? count( $this->environment_details ) : 0;
		$this->items  = array_slice( $this->environment_details, ( ( $current_page - 1 ) * $per_page ), $per_page );
		$this->set_pagination_args(
			array(
				'total_items' => $total_items,
				'per_page'    => $per_page,
			)
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
			case 'environment_id':
				return esc_html( $item->id );
			case 'environment_name':
				return esc_html( $item->environment_name );
			case 'environment_url':
				return esc_url( $item->environment_url );
			default:
				return '';
		}
	}

	/**
	 * Column actions.
	 *
	 * @param object $item Item object.
	 * @return string
	 */
	public function column_actions( $item ) {
		if ( ! empty($this->current_environment_details) && ( $item->environment_name === $this->current_environment_details->environment_name || $item->environment_url === $this->current_environment_details->environment_url ) ) {
			$disable_delete_button = 'disabled';
			$current_environment   = true;
		} else {
			$disable_delete_button = '';
			$current_environment   = false;
		}

		$idp_details = DB_Utils::get_records( Constants::DATABASE_TABLE_NAMES['idp_details'], array( 'environment_id' => $item->id ) );
		$idp_names   = array();
		if ( ! empty( $idp_details ) ) {
			foreach ( $idp_details as $idp ) {
				if ( 'All IDPs' !== $idp->idp_name ) {
					$idp_names[] = $idp->idp_name;
				}
			}
		}
		$idp_names_json = wp_json_encode( $idp_names );

		ob_start();
		?>
		<span class="mosaml-action-icon" data-tooltip="Edit" <?php echo esc_attr( $this->disable_multiple_environment_option ); ?>>
			<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" onclick="editEnvironmentModal('<?php echo esc_attr( $item->id ); ?>', '<?php echo esc_attr( $item->environment_name ); ?>', '<?php echo esc_attr( $item->environment_url ); ?>', '<?php echo esc_attr( $current_environment ); ?>')">
				<path d="M20.548 3.452a1.542 1.542 0 0 1 0 2.182l-7.636 7.636-3.273 1.091 1.091-3.273 7.636-7.636a1.542 1.542 0 0 1 2.182 0zM4 21h15a1 1 0 0 0 1-1v-8a1 1 0 0 0-2 0v7H5V6h7a1 1 0 0 0 0-2H4a1 1 0 0 0-1 1v15a1 1 0 0 0 1 1z"/>
			</svg>
		</span>
		<span class="mosaml-action-icon" data-tooltip="Delete" <?php echo esc_attr( $this->disable_multiple_environment_option ); ?> <?php echo ' ' . esc_attr( $disable_delete_button ); ?>>
			<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" onclick="deleteEnvironmentModal('<?php echo esc_attr( $item->id ); ?>', '<?php echo esc_attr( $item->environment_name ); ?>', '<?php echo esc_attr( $current_environment ); ?>', <?php echo esc_attr( $idp_names_json ); ?>)">
				<path d="M5.755 20.283 4 8h16l-1.755 12.283A2 2 0 0 1 16.265 22h-8.53a2 2 0 0 1-1.98-1.717zM21 4h-5V3a1 1 0 0 0-1-1H9a1 1 0 0 0-1 1v1H3a1 1 0 0 0 0 2h18a1 1 0 0 0 0-2z"/>
			</svg>
		</span>
		<?php
		return ob_get_clean();
	}

	/**
	 * Display when no items found.
	 *
	 * @return void
	 */
	public function no_items() {
		?>
		<span class="mosaml-no-items-message">
			You have not configured any Environment yet. Click on <b>Add New Environment</b> button to configure your Environment.
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
		?>
		<p class="search-box">
			<label class="screen-reader-text" for="<?php echo esc_attr( $input_id ); ?>"><?php echo esc_html( $text ); ?>:</label>
			<input type="search" id="<?php echo esc_attr( $input_id ); ?>" name="s" value="<?php _admin_search_query(); ?>" placeholder="Search your Environment" />
			<?php submit_button( $text, 'primary button-large', '', false, array( 'id' => 'search-submit' ) ); ?>
		</p>
		<?php
	}
}
