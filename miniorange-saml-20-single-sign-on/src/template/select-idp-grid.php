<?php
/**
 * Template for Identity Provider selection grid.
 *
 * @package miniorange-saml-20-single-sign-on
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use MOSAML\SRC\Constant\Constants;

?>

<div id="mo_saml_idps_grid_form" class="mosaml-tab-content-section mosaml-margin-top-bottom-0-2-rem">
	<form id="mo_saml_idps_grid_form" method="post" action="" class="mosaml-idp-grid-form">
		<table class="mosaml-idp-grid-table">
			<tr>
				<td>
					<h3 class="mosaml-idp-grid-heading">
						Select your Identity Provider
						<span class="dashicons dashicons-info-outline mosaml-info-icon mosaml-info-position" title="Select your Identity Provider from the list below, and you can find the link to the guide for setting up SAML below. Please contact us if you don't find your IDP in the list."></span>
						<span id="configure-service-restart-tour" class="mosaml-restart-tour-span">
						</span>
					</h3>
					<br>
				</td>
			</tr>
			<tr>
				<td colspan="2">
					<input type="text" 
							id="mo_saml_search_idp_list" 
							class="mosaml-idp-search-input" 
							placeholder="Start typing your identity provider name here.." />
				</td>
			</tr>
			<tr>
				<td colspan="2">
					<br>
					<span id="mo_saml_search_custom_idp_message" class="mosaml-custom-idp-message">
						It looks like your identity provider is not listed below, you can select<strong> Custom IDP </strong>to configure the plugin. Please send us query using support form given aside for more details
					</span>
				</td>
			</tr>
			<tr class="mosaml-idp-grid-container-row">
				<td colspan="2" class="mosaml-idp-grid-container-cell">
					<div id="mo_saml_idps_grid_div" class="mosaml-idp-grid-div mosaml-grid-collapsed">
						<ul class="mosaml-idp-grid-list">
							<?php
							if ( is_array( Constants::IDP_GUIDES ) ) :
								$idp_counter = 0;
								foreach ( Constants::IDP_GUIDES as $key => $value ) :
									if ( ! is_array( $value ) || ! isset( $value[0] ) || ! isset( $value[1] ) ) {
										continue;
									}

									$idp_logo_name   = isset( $value[0] ) ? $value[0] : '';
									$idp_guide_path  = isset( $value[1] ) ? $value[1] : '';
									$idp_video_index = ( is_array( Constants::IDP_VIDEOS ) && isset( Constants::IDP_VIDEOS[ $idp_logo_name ] ) ) ? Constants::IDP_VIDEOS[ $idp_logo_name ] : '';

									if ( empty( $key ) || ! is_string( $key ) ) {
										continue;
									}

									$image_file_path = Constants::PLUGIN_NAME . '/static/image/idp-logos/' . $idp_logo_name . '.webp';
									++$idp_counter;

									$item_class = $idp_counter > 8 ? 'mosaml-idp-grid-item mosaml-idp-hidden' : 'mosaml-idp-grid-item';
									?>
									<li class="<?php echo esc_attr( $item_class ); ?>">
										<a target="_blank" 
											class="mosaml-idp-grid-link" 
											data-idp-value="<?php echo esc_attr( $idp_video_index ); ?>"
											data-href="https://plugins.miniorange.com/<?php echo esc_attr( $idp_guide_path ); ?>"
											data-video="https://www.youtube.com/watch?v=<?php echo esc_attr( $idp_video_index ); ?>"
											data-idp-name="<?php echo esc_attr( $key ); ?>"
											data-idp-image="<?php echo esc_url( plugins_url( $image_file_path ) ); ?>">
											<img src="<?php echo esc_url( plugins_url( $image_file_path ) ); ?>" 
												alt="<?php echo esc_attr( $key ); ?>" 
												class="mosaml-idp-grid-image" 
												onerror="this.style.display='none';" />
											<br>
											<h4 class="mosaml-idp-grid-title"><?php echo esc_html( $key ); ?></h4>
										</a>
									</li>
									<?php
								endforeach;
							endif;
							?>
						</ul>
						
					</div>

					<?php if ( is_array( Constants::IDP_GUIDES ) && count( Constants::IDP_GUIDES ) > 8 ) : ?>
						<div class="mosaml-show-more-container">
							<a href="javascript:void(0);" id="mosaml-show-more-idps" class="mosaml-show-more-btn" onclick="toggleIdpGrid()">
								Show More ▼
							</a>
						</div>
					<?php endif; ?>
				</td>
			</tr>
		</table>
	</form>
</div>

