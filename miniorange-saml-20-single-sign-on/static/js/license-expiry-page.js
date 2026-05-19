jQuery(document).ready(function ($) {

	function normalizeAdminPageUrlForRedirectCheck(url) {
		return String(url).split('#')[0].split('?')[0].replace(/\/$/, '');
	}

	const renewalFAQUrl = mosaml_grace_notice_data.renewal_faq_url;
	const renewalFAQBtn = $('#mosaml_grace_notice_faq_btn');
	const cancelBtn = $('#mosaml_grace_notice_cancel_btn');

	renewalFAQBtn.on('click', function () {
		window.open(renewalFAQUrl, '_blank');
		reloadGraceNotice();
	});
	cancelBtn.on('click', function () {
		reloadGraceNotice();
	});

	function reloadGraceNotice() {
		window.location.reload();
	}

	function fadeOutGraceNotice() {
		$('.mosaml-grace-notice-overlay').fadeOut(400);
	}

	const graceNoticeSyncLicenseBtn = $('#mosaml_grace_notice_sync_license_btn');
	graceNoticeSyncLicenseBtn.on('click', function (e) {
		e.preventDefault();
		console.log('executing mo_saml_grace_sync_license');
		const btn = $(this);

		btn.prop('disabled', true)
			.removeClass('mosaml-plain-notice-btn')
			.addClass('mosaml-grace-sync-message')
			.html('<span class="loader"></span> Syncing your license...');

		$.ajax({
			url: mosaml_grace_notice_data.ajax_url,
			type: 'POST',
			data: {
				action: 'mosaml_expiry_page_license_sync',
				nonce: mosaml_grace_notice_data.nonce
			},
			success: function (response) {
				console.log('License sync response:', response);

				if (response.success) {
					btn.html('<img width="30" height="30" src="' + mosaml_grace_notice_data.success_icon + '" alt="Success Icon" class="mosaml-grace-notice-icon">' + response.data.message);
					setTimeout(function () {
						fadeOutGraceNotice();
					}, 1000);
				} else {
					btn.html('<img width="30" height="30" src="' + mosaml_grace_notice_data.error_icon + '" alt="Error Icon" class="mosaml-grace-notice-icon">' + response.data.message);
				}
			},
			error: function (xhr, status, error) {
				console.log('AJAX Error:', error);
				btn.html('<img width="20" height="20" src="' + mosaml_grace_notice_data.error_icon + '" alt="Error Icon" class="mosaml-grace-notice-icon"> Something went wrong.');
			}
		});
	});

	const graceDeactivatePluginBtn = $('#mosaml_grace_notice_deactivate_btn');
	graceDeactivatePluginBtn.on('click', function (e) {
		e.preventDefault();
		const deactivateButton = $(this);
		const shouldRedirectToPluginsPage =
			mosaml_grace_notice_data.redirect_after_grace_expired_notice &&
			mosaml_grace_notice_data.plugins_page_url &&
			normalizeAdminPageUrlForRedirectCheck(window.location.href) !==
				normalizeAdminPageUrlForRedirectCheck(mosaml_grace_notice_data.plugins_page_url);

		if (shouldRedirectToPluginsPage) {
			if (
				!window.confirm(
					'Your license grace period has ended. The plugin will be deactivated and you will be taken to the Plugins page. Click OK to continue.'
				)
			) {
				return;
			}
		}

		deactivateButton.prop('disabled', true).html('Deactivating plugin...');
		$.ajax({
			url: mosaml_grace_notice_data.ajax_url,
			type: 'POST',
			data: {
				action: 'mosaml_deactivate_plugin',
				nonce: mosaml_grace_notice_data.nonce
			},
			success: function (response) {
				if (response.success) {
					if (shouldRedirectToPluginsPage) {
						window.location.assign(mosaml_grace_notice_data.plugins_page_url);
					} else {
						alert('Plugin deactivated successfully');
						window.location.reload();
					}
				} else {
					deactivateButton.prop('disabled', false).html('Deactivate Plugin');
					alert('Error: ' + response.data.message);
				}
			},
			error: function (xhr, status, error) {
				deactivateButton.prop('disabled', false).html('Deactivate Plugin');
				alert('Error: ' + error);
			}
		});
	});
});
