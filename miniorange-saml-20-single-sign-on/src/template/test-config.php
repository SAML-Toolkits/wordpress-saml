<?php
/**
 * Test Configuration Template
 *
 * @package miniorange-saml-20-single-sign-on
 */
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template scope variables.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div class="wrap">
	<div class="test-config-container">
		<?php
		if ( $show_error_message ) :
			?>
			<div class="test-error-header">
				ERROR
			</div>
			<div class="test-error-content mosaml-width-70">
				<p><strong>Code: </strong><?php echo esc_attr( $error_code['code'] ); ?></p>
				<p><strong>Error: </strong><?php echo esc_attr( $error_code['cause'] ); ?></p>
				<?php if ( ! empty( $error_code['test_config_msg'] ) ) : ?>
					<p><strong>Possible Cause: </strong><?php echo esc_attr( $error_code['test_config_msg'] ); ?></p>
				<?php endif; ?>
				<?php if ( ! empty( $details ) && is_array( $details ) && ! empty( $details['to_show'] ) ) : ?>
					<?php
					foreach ( $details['to_show'] as $key => $value ) {
						echo wp_kses_post( '<strong>' . $key . ': </strong><br/>' );
						echo '<pre>' . wp_kses_post( $value ) . '</pre>';
					}
					?>
				<?php endif; ?>
				<p><strong>Solution:</strong></p>
				<?php
				echo wp_kses_post( $error_code['fix'] );
				?>
			</div>
			<form id="mosaml_fix_test_config_issue" method="post" action="">
				<?php wp_nonce_field( 'mosaml_fix_test_config_issue' ); ?>
				<input type="hidden" name="option" value="mosaml_fix_test_config_issue">
				<input type="hidden" name="details" value='<?php echo wp_json_encode( isset( $details ) && is_array( $details ) && isset( $details['to_update'] ) ? $details['to_update'] : array() ); ?>'>
			</form>
			<div class="test-button-container">
				<?php if ( ! empty( $details ) && is_array( $details ) && ! empty( $details['to_update'] ) ) : ?>
					<input class="button button-primary button-large mosaml-test-button" type="button" value="Fix Issue" onclick="document.getElementById('mosaml_fix_test_config_issue').submit()"/>
				<?php endif; ?>
				<input class="button button-primary button-large mosaml-test-button" type="button" value="Done" onClick="closeAndRefresh()"/>
			</div>
			<?php
		else :
			if ( ! empty( $idp_attributes['NameID'] ) ) :
				?>
				<div class="test-message test-success">TEST SUCCESSFUL</div>
				<div class="test-image-container">
					<img class="test-image" src="<?php echo esc_url( plugins_url( 'static/image/green_check.webp', dirname( __DIR__, 2 ) . '/login.php' ) ); ?>" alt="Success Check">
				</div>
				<?php
			else :
				?>
				<div class="test-message test-failed">TEST FAILED</div>
				<?php if ( ! $end_user_test ) : ?>
					<div class="test-warning">WARNING: Some Attributes Did Not Match.</div>
				<?php endif; ?>
				<div class="test-image-container">
					<img class="test-image" src="<?php echo esc_url( plugins_url( 'static/image/wrong.webp', dirname( __DIR__, 2 ) . '/login.php' ) ); ?>" alt="Wrong Check">
				</div>
				<?php
			endif;
			if ( ! $end_user_test ) :
				if ( ! empty( $idp_attributes ) ) :
					?>
					<span class="test-greeting test-text-14pt"><b>Hello</b>, <?php echo esc_html( $idp_attributes['NameID'] ); ?></span><br/>
					<p class="test-attributes-title test-text-14pt">ATTRIBUTES RECEIVED:</p>
					<table class="test-table">
						<tr class="test-table-header">
							<td class="test-table-cell test-table-header-cell">ATTRIBUTE NAME</td>
							<td class="test-table-cell test-table-header-cell-value">ATTRIBUTE VALUE</td>
						</tr>
						<?php
						foreach ( $idp_attributes as $key => $value ) :
							?>
							<tr>
								<td class="test-table-cell test-table-cell-name"><?php echo esc_html( $key ); ?></td>
								<?php if ( is_array( $value ) ) : ?>
									<td class="test-table-cell"><?php echo implode( '<hr/>', map_deep( $value, 'esc_html' ) ); ?></td>
								<?php else : ?>
									<td class="test-table-cell"><?php echo esc_html( $value ); ?></td>
								<?php endif; ?>
							</tr>
						<?php endforeach; ?>
					</table>
					<?php
				else :
					?>
					<p class="test-attributes-title test-text-14pt">No Attributes Received.</p>
					<?php
				endif;
				?>
				</div>
				<div class="test-button-container">
					<?php
					if ( ! empty( $idp_attributes ) ) :
						?>
						<input class="button button-primary button-large mosaml-test-button" id="redirect-button" type="button" value="<?php echo esc_attr( $redirect_button_text ); ?>" onClick="closeAndRedirect('<?php echo esc_url( $redirect_url ); ?>');">
					<?php endif; ?>
					<input class="button button-primary button-large mosaml-test-button" id="done-button" type="button" value="Done" onClick="closeAndRefresh()">
				</div>
			<?php else : ?>
				<?php if ( ! empty( $idp_attributes['NameID'] ) && ! empty( $idp_id ) ) : ?>
					<div class="test-button-container">
						<input class="button button-primary button-large mosaml-test-button" id="continue-to-site-button" type="button" value="Continue to Site" onClick="window.location.href='<?php echo esc_url( add_query_arg( array( 'option' => 'saml_user_login', 'idp' => $idp_id ), site_url( '/' ) ) ); ?>';">
					</div>
				<?php endif; ?>
			<?php endif; ?>
		<?php endif; ?>
	</div>
</div>

<script>
	function closeAndRedirect(url) {
		if (window.opener && !window.opener.closed) {
			// Window was opened by script, update opener and close
			window.opener.location.href = url;
			// Only close if window was opened by script (check opener exists)
		} else {
			window.location.href = url;
		}
		setTimeout(function() {
			try {
				window.close();
			} catch (e) {
				// If close fails, redirect current window instead
				window.location.href = url;
			}
		}, 100);
	}
 
	function closeAndRefresh() {
		if (window.opener && !window.opener.closed) {
			// Window was opened by script, reload opener and close
			window.opener.location.reload();
			// Only close if window was opened by script (check opener exists)
		}
		setTimeout(function() {
			try {
				window.close();
			} catch (e) {
				// If close fails, reload current window instead
				window.location.reload();
			}
		}, 100);
	}

	function hideConfigureAttributeMappingButton() {
		var configureAttributeMappingBtn = document.getElementById("redirect-button");
		if ( configureAttributeMappingBtn && ! ( window.opener && ! window.opener.closed ) ) {
			configureAttributeMappingBtn.style.display = "none";
		}
	}
	hideConfigureAttributeMappingButton();
</script>

<style>
.test-config-container {
	font-family: Calibri;
	padding: 0 3%;
}

.test-error-header {
	color: #a94442;
	background-color: #f2dede;
	padding: 15px;
	margin-bottom: 20px;
	text-align: center;
	border: 1px solid #E6B3B2;
	font-size: 18pt;
}

.test-error-content {
	color: #a94442;
	font-size: 14pt;
	margin-bottom: 20px;
}

.test-message {
	padding: 2%;
	margin-bottom: 1.25rem;
	text-align: center;
	font-size: 18pt;
}

.test-success {
	color: #3c763d;
	background-color: #dff0d8;
	border: 1px solid #AEDB9A;
}

.test-failed {
	color: #a94442;
	background-color: #f2dede;
	padding: 0.9375rem;
	border: 1px solid #E6B3B2;
}

.test-warning {
	color: #a94442;
	font-size: 14pt;
	margin-bottom: 1.25rem;
}

.test-image-container {
	display: block;
	text-align: center;
	margin-bottom: 4%;
}

.test-image {
	width: 15%;
}

.test-text-14pt {
	font-size: 14pt;
}

.test-greeting {
	font-size: 14pt;
}

.test-attributes-title {
	font-weight: bold;
	font-size: 14pt;
}

.test-table {
	border-collapse: collapse;
	border-spacing: 0;
	width: 100%;
	font-size: 14pt;
	background-color: #EDEDED;
	table-layout: fixed;
}

.test-table-header {
	text-align: center;
}

.test-table-cell {
	border: 2px solid #949090;
	padding: 2%;
	width: 50%;
	word-wrap: break-word;
}

.test-table-header-cell {
	font-weight: bold;
}

.test-table-header-cell-value {
	font-weight: bold;
}

.test-table-cell-name {
	font-weight: bold;
}

.test-button-container {
	margin: 3% 0;
	display: block;
	text-align: center;
}

.test-button-container .button {
	margin: 0 5px;
}

/* WordPress button styles for test config page */
.mosaml-test-button {
	display: inline-block;
	text-decoration: none;
	font-size: 13px;
	line-height: 2.15384615;
	min-height: 30px;
	margin: 0;
	padding: 0 10px;
	cursor: pointer;
	border-width: 1px;
	border-style: solid;
	-webkit-appearance: none;
	appearance: none;
	border-radius: 3px;
	white-space: nowrap;
	box-sizing: border-box;
	background: #2271b1;
	border-color: #2271b1;
	color: #fff;
	text-shadow: none;
	font-weight: 400;
	font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
}

.mosaml-test-button.button-large {
	height: auto;
	padding: 9px 20px;
	font-size: 14px;
	line-height: 1.71428571;
}

.mosaml-test-button:hover {
	background: #135e96;
	border-color: #135e96;
	color: #fff;
}

.mosaml-test-button:focus {
	background: #135e96;
	border-color: #135e96;
	color: #fff;
	box-shadow: 0 0 0 1px #fff, 0 0 0 3px #2271b1;
	outline: 2px solid transparent;
	outline-offset: 2px;
}

.mosaml-test-button:active {
	background: #0a4b78;
	border-color: #0a4b78;
	color: #fff;
}
</style>
