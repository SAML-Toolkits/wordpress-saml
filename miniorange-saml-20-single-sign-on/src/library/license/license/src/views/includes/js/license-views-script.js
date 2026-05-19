jQuery(document).ready(function($) {

	window.mo_install_addon = function(download_url, addon_name, btn) {
		if (btn) {
			btn.disabled = true;
			btn.innerHTML = '<p style="color: #fff; margin: 0px;">Activating<span class="mo-activate-loader"></span></p>';
		}

		$.ajax({
			url: ajaxurl,
			type: 'POST',
			data: {
				action: 'mo_install_addon',
				download_url: download_url,
				addon_name: addon_name,
				nonce: moAddonsData.nonce
			},
			success: function(response) {
				if (response.success) {
					location.reload();
				} else {
                    location.reload();
				}
			},
			error: function() {
                location.reload();
			}
		});
	};
});