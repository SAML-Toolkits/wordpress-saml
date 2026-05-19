/**
 * Login Page SSO Button JavaScript
 *
 * @package miniorange-saml-20-single-sign-on
 */

window.onload = function () {
	var buttons = document.getElementsByName("mo_saml_button");
	var loginForm = document.getElementById("loginform");
	if (!buttons.length || !loginForm) return;

	var above = [], below = [];
	Array.from(buttons).forEach(function (btn) {
		(btn.getAttribute('data-position') === 'below' ? below : above).push(btn);
	});

	var firstP = loginForm.querySelector("p");
	if (firstP && above.length) {
		above.forEach(function (btn) { firstP.before(btn); });
	}

	var submitBtn = loginForm.querySelector("p.submit");
	submitBtn = submitBtn ? submitBtn : firstP;
	if (below.length) {
		below.forEach(function (btn) {
			submitBtn ? submitBtn.parentNode.insertBefore(btn, submitBtn.nextSibling) : loginForm.parentNode.insertBefore(btn, loginForm.nextSibling);
		});
	}
};

document.addEventListener('DOMContentLoaded', function () {
	document.querySelectorAll('[id^="mo_saml_login_sso_button_"]').forEach(function (btn) {
		btn.addEventListener('click', function () {
			var container = this.closest('[name="mo_saml_button"]');
			var input = document.getElementById('saml_user_login_input_' + (container ? container.getAttribute('data-idp-id') : ''));
			var form = document.getElementById('loginform');
			var idpId = container ? container.getAttribute('data-idp-id') : '';
			var base = container ? (container.getAttribute('data-sso-base') || '') : '';
			if (!base) {
				base = (window.location && window.location.origin) ? (window.location.origin + '/') : '/';
			}
			var targetUrl = base.replace(/\/+$/, '/') + '?option=saml_user_login' + '&idp=' + encodeURIComponent(idpId);
			var redirectToParam = null;
			try {
				var params = new URLSearchParams(window.location.search || '');
				if (params.has('redirect_to')) {
					redirectToParam = params.get('redirect_to');
					targetUrl += '&redirect_to=' + encodeURIComponent(redirectToParam);
				}
			} catch (e) { }

			window.location.href = targetUrl;
		});
	});
});

jQuery(document).ready(function ($) {
	let loginUserViaForm = false;
	if (moSamlLoginData.isBackdoorLogin) {
		return;
	}
	if (moSamlLoginData.domainMappingEnabled && moSamlLoginData.domainMappingEnabled === 'checked') {
		hideElements();
		$('#loginform').on('submit', function (e) {
			handleLoginFormSubmission(e);
		});
	}

	function hideElements() {
		const hideElements = [
			'#user_pass',
			'label[for="user_pass"]',
			'#rememberme',
			'label[for="rememberme"]',
			'button[aria-label="Show password"]',
			'#nav',
		];

		hideElements.forEach(function (selector) {
			$(selector).hide();
		});
		$('label[for="user_login"]').text('Email Address');
		$('#user_pass').removeAttr('required').attr('disabled', 'disabled');
	}

	function handleLoginFormSubmission(e) {
		if (loginUserViaForm) {
			return;
		}
		e.preventDefault();
		const userEmail = $('#user_login').val();
		if (!userEmail || userEmail.length === 0) {
			showError('Please enter your email address.');
			return;
		}
		if (!checkEmail(userEmail)) {
			showError('Please enter a valid email address.');
			return;
		}
		fetchDomainMappingResponse(userEmail);
	}

	function fetchDomainMappingResponse(userEmail) {
		$.ajax({
			url: moSamlLoginData.ajaxUrl,
			method: "GET",
			data: {
				action: "mosaml_fetch_domain_mapping",
				userEmail: userEmail,
				_ajax_nonce: moSamlLoginData.nonce
			},
			success: function (response) {
				if (response.data.status === 'redirect') {
					window.location.href = response.data.url;
				} else if (response.data.status === 'wp_login') {
					loginUserViaForm = true;
					showElements();
				}
			},
			error: function (error) {
				loginUserViaForm = true;
				showElements();
			}
		});
	}

	function showElements() {
		const showElements = [
			'#user_pass',
			'label[for="user_pass"]',
			'#rememberme',
			'label[for="rememberme"]',
			'button[aria-label="Show password"]',
			'#nav',
		];
		showElements.forEach(function (selector) {
			$(selector).show();
		});
		$('#user_pass').removeAttr('disabled').attr('required', 'required');
		$('#login_error').hide();
	}

	function checkEmail(email) {
		if (!email || typeof email !== "string") {
			return null;
		}
		const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
		return emailRegex.test(email.trim());
	}

	function showError(message) {
		const errorDiv = $('#login_error');
		if (errorDiv.length > 0) {
			errorDiv.html(`<p><strong>Error:</strong> ${message}</p>`);
		} else {
			$('#loginform').before(`<div id="login_error" class="notice notice-error"><p><strong>Error:</strong> ${message}</p></div>`);
		}
	}
});

