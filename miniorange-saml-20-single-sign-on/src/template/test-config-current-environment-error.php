<?php
/**
 * Test Configuration Template
 *
 * @package miniorange-saml-20-single-sign-on
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<div class="wrap">
	<div class="test-config-container">
		<div class="test-error-header">
			ERROR
		</div>
		<div class="test-error-content mosaml-width-70">
			<p>
				You have selected the <b> <?php echo esc_html( $selected_environment_name ); ?> </b> environment which is not your current environment. As per the SAML protocol you can only perform test configuration for an environment after you migrate to it.<br><br>
				<b>Note:</b> You can test the configurations for your current environment (<b> <?php echo esc_html( $current_environment_name ); ?> </b>) after switching to it in the plugin. If you wish to do so please click on the Select Current Environment button below and click on Test Configuration for your IDP.
			</p>
		</div>
		<form method="post" action="" id="<?php echo esc_attr( $current_environment_name . '_form' ); ?>">
			<?php
			if ( function_exists( 'wp_nonce_field' ) ) {
				call_user_func( 'wp_nonce_field', 'mosaml_change_environment' );
			} else {
				echo '<input type="hidden" name="_wpnonce" value="" />';
			}
			?>
			<input type="hidden" name="option" value="mosaml_change_environment"/>
			<input type="hidden" name="environment" value="<?php echo esc_html( $current_environment_name ); ?>"/>
		</form>
		<div class="test-button-container">
			<input class="button button-primary button-large mosaml-test-button" type="button" value="Select Current Environment" onclick="submitSelectEnvironmentForm()"/>
			<input class="button button-primary button-large mosaml-test-button" type="button" value="Close" onClick="closeAndRefresh()"/>
		</div>		
	</div>
</div>

<script>
	function submitSelectEnvironmentForm() {
		var url = "<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>";

		var formData = new FormData();
		formData.append("action", "mosaml_change_environment");
		formData.append("environment", "<?php echo esc_js( $current_environment_name ); ?>");
		formData.append("nonce", "<?php echo esc_attr( wp_create_nonce( 'mosaml_change_environment' ) ); ?>");

		fetch(url, {
			method: "POST",
			credentials: "same-origin",
			body: formData
		})
		.then(response => response.json())
		.then(data => {
			if (data.success) {
				alert(data.data.message || "Environment updated successfully.");

				if (window.opener && !window.opener.closed) {
					window.opener.location.reload();
				}
				window.close();
			} else {
				alert(data.data?.message || "Something went wrong. Please try again.");
			}
		})
		.catch(error => {
			alert("Network error occurred. Please check your connection and try again.");
		});
	}



	function closeAndRefresh() {
		if (window.opener && !window.opener.closed) {
			window.opener.location.reload();
		}
		setTimeout(function() {
			try {
				window.close();
			} catch (e) {
				window.location.reload();
			}
		}, 100);
	}
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
