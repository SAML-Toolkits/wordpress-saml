jQuery(document).ready(function ($) {

	function syncLicense() {
		$.ajax({
			url: moSamlAjax.ajax_url,
			type: "POST",
			data: {
				action: "mosaml_sync_license_on_expiry",
				_ajax_nonce: moSamlAjax.nonce
			},
			success: function (response) {
				if (response.success) {
					if (response.data.remaining_days !== 'undefined') {
						hideNoticeAndUpdateExpiryDate(response.data.expiry_date, response.data.last_synced, response.data.remaining_days);
					}
				}
			}
		}).always(function () {
			document.getElementById("mo-saml-license-sync-loader").style.display = "none";
		});
	}

	if (parseInt(moSamlAjax.remaining_days) < 0) {
		const loader = document.getElementById("mo-saml-license-sync-loader");
		if (loader) {
			loader.style.display = "block";
		}
		syncLicense();
	}
});

function hideNoticeAndUpdateExpiryDate(expiry_date, last_synced, remaining_days) {
	document.getElementById("mo_saml_last_synced").textContent = last_synced;
	document.getElementById("mo_saml_license_expiry").textContent = expiry_date;
	if (remaining_days > 0) {
		document.getElementById("mo_saml_profile_box_expiry_notice").style.display = "none";
	}
}