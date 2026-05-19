function copyToClipboard(copyButton, element, copyelement) {
	var temp = jQuery("<input>");
	jQuery("body").append(temp);
	temp.val(jQuery(element).text()).select();
	document.execCommand("copy");
	temp.remove();
	jQuery(copyelement).text("Copied");

	jQuery(copyButton).mouseout(function () {
		jQuery(copyelement).text("Copy to Clipboard");
	});
}

function submitHideWpLoginForm() {
	const hideWpLoginForm = document.getElementById('mosaml_enable_hide_wp_login_form');
	if (hideWpLoginForm) {
		hideWpLoginForm.querySelectorAll(":disabled").forEach(function (el) {
			el.disabled = false;
		});
		hideWpLoginForm.submit();
	}
}

function copyToClipboards(copyButton, copyelement, sp_base_url, redirect_to) {
	var redirect_to = redirect_to == 0 ? "" : "&redirect_to=page_url";
	var copy_text_temp_input = jQuery("<input>");
	jQuery("body").append(copy_text_temp_input);
	copy_text_temp_input.val(sp_base_url + "?option=saml_user_login&idp=" + jQuery("#saml_select_idp_name").val() + redirect_to).select();
	document.execCommand("copy");
	copy_text_temp_input.remove();
	jQuery(copyelement).text("Copied");

	jQuery(copyButton).mouseout(function () {
		jQuery(copyelement).text("Copy to Clipboard");
	});
}

function mosaml_submit_form_callback(vars) {
	console.log("inside submit");
	if (vars.formId) {
		jQuery("#" + vars.formId).submit();
	}
}

function resetConfigurationPrompt(formToSubmit, confirmationMessage) {
	mosaml_showModal({
		title: 'Confirm',
		message: confirmationMessage,
		buttons: {
			'confirm': 'mosaml_submit_form_callback'
		},
		passedVars: { formId: formToSubmit }
	});
}

function copyIdpName(formType) {
	var idpNameField = document.getElementById('saml_identity_metadata_provider_common');
	if (!idpNameField.reportValidity()) {
		return false;
	}
	var idpName = idpNameField.value;
	if (formType === 'file') {
		document.getElementById('hidden_idp_name_file').value = idpName;
	} else if (formType === 'url') {
		document.getElementById('hidden_idp_name_url').value = idpName;
	}
	return true;
}

function mo_saml_handle_metadata_sync_toggle() {
	var checkbox = document.getElementById('sync_metadata');
	var container = document.getElementById('select_time_sync_metadata');
	var metadataUrlInput = document.getElementById('metadata_url');
	if (checkbox && container) {
		var isVisible = checkbox.checked;
		container.style.display = isVisible ? 'block' : 'none';
		if (metadataUrlInput) {
			if (isVisible) {
				metadataUrlInput.setAttribute('required', 'required');
			} else {
				metadataUrlInput.removeAttribute('required');
			}
		}
	}
}

function update_metadata_url_sync() {
	return true;
}

function submitSSOButtonName() {
	var idpname_ele = document.getElementById("saml_select_idp_name");
	var idp = idpname_ele.options[idpname_ele.selectedIndex].value;
	document.forms["sso_button_idp_form"].elements[0].value = idp;
	document.forms["sso_button_idp_form"].submit();
}

function changeBackdoorLogin() {
	jQuery("#backdoor_url").prop('disabled', false);
	jQuery("#mo_saml_allow_wp_signin_form").submit();
}

function copyBackdoorUrl(copyButton, loginURL) {
	var temp = jQuery("<input>");
	jQuery("body").append(temp);
	var paramSep = (loginURL && loginURL.indexOf("?") !== -1) ? "&" : "?";
	temp.val(loginURL + paramSep + "saml_sso=" + jQuery("#backdoor_url").val()).select();
	document.execCommand("copy");
	temp.remove();
	jQuery("#backdoor_url_copy").text("Copied");

	jQuery(copyButton).mouseout(function () {
		jQuery("#backdoor_url_copy").text("Copy to Clipboard");
	});
}

function checkInputValidity(textbox) {
	if (textbox.validity.patternMismatch) {
		textbox.setCustomValidity('Only Alphanumeric characters, hyphens(-) and underscores(_) are allowed.');
	} else if (textbox.validity.valueMissing) {
		textbox.setCustomValidity('This field cannot be empty.');
	} else {
		textbox.setCustomValidity('');
	}
	textbox.reportValidity();
	return true;
}

function submitDomainMappingForm() {
	const domainMappingForm = document.getElementById("saml_form_domain_mapping");
	if (domainMappingForm) {
		domainMappingForm.querySelectorAll(":disabled").forEach(function (el) {
			el.disabled = false;
		});
		domainMappingForm.submit();
	}
}

function moSamlToggleAutoRedirect(checkbox) {
	const radios = document.getElementsByName('mo_saml_auto_redirection_options');
	if (checkbox.checked) {
		radios.forEach(radio => {
			radio.disabled = false;
		});
	} else {
		radios.forEach(radio => {
			radio.disabled = true;
		});
	}
	submitAutoRedictionOptionForm();
}

function submitAutoRedictionOptionForm() {
	document.getElementById("mosaml_site_auto_redirection").submit();
}

function clickHandle(evt, animalName) {
	if (animalName === "miniorange_certificate") {
		document.getElementById("mosaml_miniorange_certificate").classList.add("mo-saml-nav-subtab-active");
		document.getElementById("mosaml_custom_certificate").classList.remove("mo-saml-nav-subtab-active");
	} else if (animalName === "custom_certificate") {
		document.getElementById("mosaml_miniorange_certificate").classList.remove("mo-saml-nav-subtab-active");
		document.getElementById("mosaml_custom_certificate").classList.add("mo-saml-nav-subtab-active");
	}
	let i, tabcontent, tablinks;

	// This is to clear the previous clicked content.
	tabcontent = document.getElementsByClassName("tabcontent");
	for (i = 0; i < tabcontent.length; i++) {
		tabcontent[i].style.display = "none";
	}

	// Set the tab to be "active".
	tablinks = document.getElementsByClassName("tablinks");
	for (i = 0; i < tablinks.length; i++) {
		tablinks[i].className = tablinks[i].className.replace(" active-cert", "");
	}

	// Display the clicked tab and set it to active.
	document.getElementById(animalName).style.display = "block";
	evt.currentTarget.className += " active-cert";
}

function applyLatestCertificate() {
	document.getElementById("mosaml_upgrade_new_certificate_form").elements["selected_idp_id"].value = document.getElementById("mosaml_cert_idp_name").value;
	document.getElementById("mosaml_upgrade_new_certificate_form").submit();
}

jQuery(document).ready(function ($) {
	const bulkActionSelectorTop = document.getElementById('bulk-action-selector-top');
	const applyButton = document.getElementById('doaction');
	if (bulkActionSelectorTop && applyButton) {
		bulkActionSelectorTop.disabled = !mosamlSettings.featureAvailable;
		applyButton.disabled = !mosamlSettings.featureAvailable;
	}
	$("#mo_saml_show_site_url").click(function (e) {
		e.preventDefault();
		$("#mo_saml_site_url_steps").slideToggle(400);
	});

	$(document).on("click", "#mo_saml_profile_box_expiry_notice", function (e) {
		e.preventDefault();
		e.stopPropagation();
		var $notice = $(this);
		var $warningAnswer = $("#mo_saml_warning_answer");
		var $answer = $notice.next();

		$notice.toggleClass("active");

		if ($notice.hasClass("active")) {
			$answer.css({
				"border-bottom": "1.3px solid #f0d480",
				"border-top": "none",
				"margin-top": "0",
				"border-left": "1.3px solid #f0d480",
				"border-right": "1.3px solid #f0d480",
				"padding": "1rem",
				"border-radius": "0 0 4px 4px",
				"display": "block"
			});
			$notice.css({
				"border-bottom": "none",
				"border-radius": "4px 4px 0 0"
			});
			if ($warningAnswer.length) {
				$warningAnswer.show();
			}
		} else {
			$answer.css({
				"display": "none",
				"padding": "0rem"
			});
			$notice.css({
				"border-radius": "4px 4px 4px 4px",
				"border-bottom": "1.3px solid #f0d480"
			});
			if ($warningAnswer.length) {
				$warningAnswer.hide();
			}
		}
	});

	function checkSSOButtonType() {
		if (!$('#longButtonWithText').is(':checked')) {
			$('.longButton').hide();
			$('#commonIcon').show();
		} else {
			$('.longButton').show();
			$('#commonIcon').hide();
		}
	}
	function moPreviewButton(type, s, w, h, curve, bg, color, text, fs) {
		var $btn = $('.sso_button');
		$btn.css({
			backgroundColor: bg,
			borderColor: 'transparent',
			color: color,
			overflow: 'hidden',
			fontSize: fs + 'px',
			padding: '0px'
		}).text(text);
		if (type === 'longbutton') {
			$btn.css({ width: w + 'px', height: h + 'px', borderRadius: curve + 'px' });
		} else if (type === 'circle') {
			$btn.css({ height: s, width: s, borderRadius: '999px', paddingTop: '0px', paddingBottom: '0px' });
		} else if (type === 'oval') {
			$btn.css({ height: s, width: s, borderRadius: '5px', paddingTop: '0px', paddingBottom: '0px' });
		} else if (type === 'square') {
			$btn.css({ height: s, width: s, borderRadius: '0px', paddingTop: '0px', paddingBottom: '0px' });
		}
	}

	jQuery("#upload_certificate_modal").on("click", function () {
		jQuery("#upgrade_cert").hide();
		jQuery("#miniorange_upload").show();
	});
	jQuery("#upgrade_to_miniorange_certs").on("click", function () {
		jQuery("#miniorange_upload").hide();
		jQuery("#upgrade_cert").show();
	});

	function moSamlMaxMinLimit(attribute, min, max, value) {
		var increase = document.getElementById('increase-' + attribute);
		increase.disabled = false;
		var decrease = document.getElementById('decrease-' + attribute);
		decrease.disabled = false;
		if (value >= max) {
			increase.disabled = true;
		}
		if (value <= min) {
			decrease.disabled = true;
		}
	}

	function moLoginSizeValidate() {
		var e = document.getElementById('mo_saml_button_size');
		var val = e.value;
		moSamlMaxMinLimit('size', 20, 70, val);
		if (!val.match(/^\d+$/) || val.trim() == "") {
			e.value = 20;
		}
		var t = parseInt(e.value.trim());
		if (t > 70) e.value = 70;
		if (t < 20) e.value = 20;
	}
	function moLoginWidthValidate() {
		var e = document.getElementById('mo_saml_button_width');
		var val = e.value;
		moSamlMaxMinLimit('width', 100, 270, val);
		if(!val.match(/^\d+$/) || val.trim() == ""){
			e.value = 100;
		}
		var t=parseInt(e.value.trim());t>270?e.value=270:100>t&&(e.value=100)
	}
	function moLoginHeightValidate() {
		var e = document.getElementById('mo_saml_button_height');
		var val = e.value;
		moSamlMaxMinLimit('height', 30, 70, val);
		if (!val.match(/^\d+$/) || val.trim() == "") {
			e.value = 30;
		}
		var t = parseInt(e.value.trim());
		if (t > 70) e.value = 70;
		if (t < 30) e.value = 30;
	}
	function moLoginCurveValidate() {
		var e = document.getElementById('mo_saml_button_curve');
		var val = e.value;
		moSamlMaxMinLimit('curve', 0, 30, val);
		if (!val.match(/^\d+$/) || val.trim() == "") {
			e.value = 0;
		}
		var t = parseInt(e.value.trim());
		if (t > 30) e.value = 30;
		if (t < 0) e.value = 0;
	}
	function moLoginFontSizeValidate() {
		var e = document.getElementById('mo_saml_font_size');
		var val = e.value;
		moSamlMaxMinLimit('font-size', 10, 50, val);
		if (!val.match(/^\d+$/) || val.trim() == "") {
			e.value = 10;
		}
		var t = parseInt(e.value.trim());
		if (t > 50) e.value = 50;
		if (t < 10) e.value = 10;
	}
	function moLoginValidateButtonText() {
		var e = document.getElementById('mo_saml_button_text');
		var val = e.value;
		if (val.trim() == "") {
			val = "##IDP##";
		}
		// Optionally replace ##IDP## with a value from a data attribute or global var
		if (window.mo_saml_idp_name) {
			val = val.replace("##IDP##", window.mo_saml_idp_name);
		}
		e.value = val;
	}
	function moLoginValidateButtonColor() {
		var e = document.getElementById('mo_saml_button_color');
		var val = e.value;
		if (val.trim() == "" || mosamlSettings.version < 3) {
			val = "#0085ba";
		}
		e.value = val;
	}
	function updatePreviewButton() {
		moPreviewButton(
			getButtonTheme(),
			$('#mo_saml_button_size').val(),
			$('#mo_saml_button_width').val(),
			$('#mo_saml_button_height').val(),
			$('#mo_saml_button_curve').val(),
			$('#mo_saml_button_color').val(),
			$('#mo_saml_font_color').val(),
			$('#mo_saml_button_text').val(),
			$('#mo_saml_font_size').val()
		);
	}
	function increaseValue($el) { $el.val(Number($el.val()) + 1); }
	function decreaseValue($el) { $el.val(Number($el.val()) - 1); }
	function getButtonTheme() { return $('input[name=mo_saml_button_theme]:checked').val(); }
	function getSizeOfIcons() {
		if ($('input[name=mo_saml_button_theme]:checked').val() == "longbutton") {
			return $('#mo_saml_button_width').val();
		} else {
			return $('#mo_saml_button_size').val();
		}
	}


	$(document).on('change', 'input[name="mo_saml_button_theme"]', function () {
		checkSSOButtonType();
		updatePreviewButton();
	});
	$(document).on('change', '#mo_saml_button_size', function () {
		moLoginSizeValidate();
		updatePreviewButton();
	});
	$(document).on('change', '#mo_saml_button_width', function () {
		moLoginWidthValidate();
		updatePreviewButton();
	});
	$(document).on('change', '#mo_saml_button_height', function () {
		moLoginHeightValidate();
		updatePreviewButton();
	});
	$(document).on('change', '#mo_saml_button_curve', function () {
		moLoginCurveValidate();
		updatePreviewButton();
	});
	$(document).on('change', '#mo_saml_font_size', function () {
		moLoginFontSizeValidate();
		updatePreviewButton();
	});
	$(document).on('change', '#mo_saml_button_text', function () {
		moLoginValidateButtonText();
		updatePreviewButton();
	});
	$(document).on('change', '#mo_saml_button_color', function () {
		moLoginValidateButtonColor();
		updatePreviewButton();
	});
	$(document).on('input change', '#mo_saml_font_color', function () {
		if (mosamlSettings.version < 3) {
			return;
		}
		updatePreviewButton();
	});

	if (mosamlSettings.version >= 3) {
		$(document).on('click', '#decrease-size', function () { decreaseValue($('#mo_saml_button_size')); moLoginSizeValidate(); updatePreviewButton(); });
		$(document).on('click', '#increase-size', function () { increaseValue($('#mo_saml_button_size')); moLoginSizeValidate(); updatePreviewButton(); });
		$(document).on('click', '#decrease-width', function () { decreaseValue($('#mo_saml_button_width')); moLoginWidthValidate(); updatePreviewButton(); });
		$(document).on('click', '#increase-width', function () { increaseValue($('#mo_saml_button_width')); moLoginWidthValidate(); updatePreviewButton(); });
		$(document).on('click', '#decrease-height', function () { decreaseValue($('#mo_saml_button_height')); moLoginHeightValidate(); updatePreviewButton(); });
		$(document).on('click', '#increase-height', function () { increaseValue($('#mo_saml_button_height')); moLoginHeightValidate(); updatePreviewButton(); });
		$(document).on('click', '#decrease-curve', function () { decreaseValue($('#mo_saml_button_curve')); moLoginCurveValidate(); updatePreviewButton(); });
		$(document).on('click', '#increase-curve', function () { increaseValue($('#mo_saml_button_curve')); moLoginCurveValidate(); updatePreviewButton(); });
		$(document).on('click', '#decrease-font-size', function () { decreaseValue($('#mo_saml_font_size')); moLoginFontSizeValidate(); updatePreviewButton(); });
		$(document).on('click', '#increase-font-size', function () { increaseValue($('#mo_saml_font_size')); moLoginFontSizeValidate(); updatePreviewButton(); });
	}

	checkSSOButtonType();
	updatePreviewButton();

	function toggleSpecialFields(idpName) {
		var idp = (idpName || '').toLowerCase();

		var pwInput = document.getElementById('saml_password_reset_url');
		var pwRow = document.getElementById('saml_pw_reset_url_row');
		var pwSpaceBelow = document.getElementById('saml_pw_reset_url_space_below');
		var showPw = (idp === 'azure b2c') || (pwInput && pwInput.value && pwInput.value.trim() !== '');
		if (pwRow) {
			pwRow.hidden = !showPw;
			if (pwSpaceBelow) { pwSpaceBelow.hidden = !showPw; }
		}

		var sloInput = document.getElementById('saml_logout_response_url');
		var sloRow = document.getElementById('saml_logout_response_url_row');
		var sloSpaceBelow = document.getElementById('saml_logout_response_url_space_below');
		var showSlo = (idp === 'custom idp') || (sloInput && sloInput.value && sloInput.value.trim() !== '');
		if (sloRow) {
			sloRow.hidden = !showSlo;
			if (sloSpaceBelow) { sloSpaceBelow.hidden = !showSlo; }
		}
	}

	var initialIdp = (document.getElementById('saml_identity_provider_guide_name') || { value: '' }).value;
	toggleSpecialFields(initialIdp);

	$('#mo_saml_search_idp_list').focus(function () {
		document.getElementById("mo_saml_idps_grid_div").style.display = "";
	});

	$('#mo_saml_search_idp_list').on('input keyup', function () {
		var value = jQuery(this).val().toLowerCase();
		var customidp = '';
		var counter = 0;
		document.getElementById('mo_saml_search_custom_idp_message').style.display = "none";

		jQuery("#mo_saml_idps_grid_div li").each(function () {
			var p = jQuery(this).find('a');
			var idpName = '';

			if (p.attr('data-idp-name')) {
				idpName = p.attr('data-idp-name').toLowerCase();
			} else {
				var di = p.html();
				if (di && di.indexOf('<br>') > -1 && di.indexOf('<h4>') > -1) {
					var parts = di.split('<br>');
					if (parts.length > 1) {
						var h4Part = parts[1];
						if (h4Part.indexOf('<h4>') > -1 && h4Part.indexOf('</h4>') > -1) {
							idpName = h4Part.split('<h4>')[1].split('</h4>')[0].toLowerCase();
						}
					}
				}
			}

			if (idpName && idpName.indexOf(value) > -1) {
				jQuery(this).css("display", "inline-block");
				counter += 1;
			} else {
				jQuery(this).css("display", "none");
			}

			if (idpName.indexOf('custom idp') > -1) {
				customidp = jQuery(this);
			}
		});

		if (counter == 0 && value !== '') {
			if (customidp.length > 0) {
				customidp.css('display', 'inline-block');
			}
			document.getElementById('mo_saml_search_custom_idp_message').style.display = "";
		}

		if (value.trim() === '') {
			initializeIdpGrid();
			var showMoreBtn = document.getElementById('mosaml-show-more-idps');
			if (showMoreBtn) {
				showMoreBtn.innerHTML = 'Show More \u22EF';
			}
		}
	});

	$("#mo_saml_idps_grid_div li a").on("click", function (e) {
		e.preventDefault();

		var idpName = $(this).data("idp-name");
		var idpImage = $(this).data("idp-image");
		var guideLink = $(this).data("href");
		var videoLink = $(this).data("video");

		$("#mo_saml_selected_idp_div").show();
		if (idpName.toLowerCase() === "custom idp") {
			$("#custom_idp_selected").show();
		} else {
			$("#custom_idp_selected").hide();
		}

		var idpIconDiv = $("#mo_saml_selected_idp_icon_div");
		if (idpIconDiv.length === 0) {
			$("#mo_saml_selected_idp_div").html('<div id="mo_saml_selected_idp_icon_div"></div>');
		}

		$("#mo_saml_selected_idp_icon_div").html(
			'<img src="' + idpImage + '" alt="' + idpName + '" style="width: 40px; height: 40px; margin-bottom: 5px;">' +
			'<h4 style="margin: 5px 0; font-size: 14px;">' + idpName + '</h4>'
		);

		$("#saml_idp_guide_link").attr("href", guideLink);

		if (videoLink && videoLink !== "https://www.youtube.com/watch?v=" && videoLink !== "") {
			$("#saml_idp_video_link").attr("href", videoLink).show();
		} else {
			$("#saml_idp_video_link").hide();
		}

		$("html, body").animate({
			scrollTop: $("#mo_saml_selected_idp_div").offset().top - 50
		}, 500);

		toggleSpecialFields(idpName);

		var idpGuideNameInput = document.getElementById('saml_identity_provider_guide_name');
		if (idpGuideNameInput) {
			idpGuideNameInput.value = idpName;
		}
	});

	$(document).on('change', 'input[name="mo_saml_enable_login_redirect"]', function () {
		$('#mo_saml_enable_redirect_form').submit();
	});

	$(document).on('change', '#mo_saml_force_authentication', function () {
		$('#mo_saml_force_authentication_form').submit();
	});

	$(document).on('change', 'input[name="mo_saml_enable_rss_access"]', function () {
		$('#mo_saml_enable_rss_access_form').submit();
	});

	$(document).on('change', '#mo_enable_multiple_environments', function () {
		$(this).closest('form').submit();
	});

	jQuery("#enable_domain_mapping").click(function (e) {
		e.preventDefault();
		jQuery("#enable_domain_mapping_desc").slideToggle(400);
	});

	jQuery("#hide_wordpress_login").click(function (e) {
		e.preventDefault;
		jQuery("#hide_wordpress_login_desc").slideToggle(400);
	});

	jQuery("#redirect_default_idp_wp").click(function (e) {
		e.preventDefault;
		jQuery("#redirect_default_idp_wp_desc").slideToggle(400);
	});

	jQuery("#backdoor_url_wp").click(function (e) {
		e.preventDefault;
		jQuery("#backdoor_url_wp_desc").slideToggle(400);
	});

	//Widget steps
	jQuery("#help_widget_steps_title").click(function () {
		jQuery("#help_widget_steps_desc").slideToggle(400);
	});

	//redirect to idp
	jQuery("#redirect_to_idp").click(function (e) {
		e.preventDefault;
		jQuery("#redirect_to_idp_desc").slideToggle(400);
	});

	jQuery("#help_complete_logout_title").click(function (e) {
		e.preventDefault;
		jQuery("#help_complete_logout_desc").slideToggle(400);
	});

	//redirect to idp
	jQuery("#force_authentication_with_idp").click(function (e) {
		e.preventDefault;
		jQuery("#force_authentication_with_idp_desc").slideToggle(400);
	});

	//redirect to idp
	jQuery("#rss_feed_toggle").click(function (e) {
		e.preventDefault;
		jQuery("#rss_feed_toggle_info").slideToggle(400);
	});

	//redirect to idp
	jQuery("#show_sso_toggle").click(function (e) {
		e.preventDefault;
		jQuery("#show_sso_toggle_info").slideToggle(400);
	});


	jQuery("#registered_only_access").click(function (e) {
		e.preventDefault;
		jQuery("#registered_only_access_desc").slideToggle(400);
	});

	jQuery("#auto_redirect_access").click(function (e) {
		e.preventDefault;
		jQuery("#auto_redirect_access_desc").slideToggle(400);
	});

	jQuery("#redirect_default_idp").click(function (e) {
		e.preventDefault;
		jQuery("#redirect_default_idp_desc").slideToggle(400);
	});

	jQuery("#help_steps_title").click(function () {
		jQuery("#help_steps_desc").slideToggle(400);
	});

	$("#doaction").addClass("button-primary button-large");

	$("[name='bulk_action_default_idp_id']").on("change", function () {
		if ($(this).val() === "") {
			$("#mosaml_bulk_action_submit").prop("disabled", true);
		} else {
			$("#mosaml_bulk_action_submit").prop("disabled", false);
		}
	});

	var doNotUpdateExistingUsersRole = document.getElementById("mo_saml_do_not_update_existing_user");
	var multiselectDropdown = document.getElementById("mo_saml_whitelist_roles_multiselect_dropdown");
	var selectAllCheckbox = document.getElementById("select_all_checkbox");
	var enableWhitelistingUsersRoles = document.getElementById("mo_saml_whitelist_existing_users_roles");
	var searchBox = document.getElementById("multiselect_search");
	var whitelistRoles = [];

	if (multiselectDropdown && selectAllCheckbox && enableWhitelistingUsersRoles && searchBox && doNotUpdateExistingUsersRole) {

		doNotUpdateExistingUsersRole.addEventListener("change", function () {
			searchBox.disabled = doNotUpdateExistingUsersRole.checked || !enableWhitelistingUsersRoles.checked;
			selectAllCheckbox.disabled = doNotUpdateExistingUsersRole.checked;
			enableWhitelistingUsersRoles.disabled = doNotUpdateExistingUsersRole.checked;
		});


		enableWhitelistingUsersRoles.addEventListener("change", function () {
			moSamlWhitelistRolesToggleSearchBox();
			if (!this.checked) {
				moSamlWhitelistRolesHideDropdown();
			}
		});

		searchBox.addEventListener("click", function (event) {
			moSamlWhitelistRolesShowDropdown();
			event.stopPropagation();
		});

		document.addEventListener("click", function (event) {
			if (!searchBox.contains(event.target) && !multiselectDropdown.contains(event.target)) {
				moSamlWhitelistRolesHideDropdown();
			}
		});

		selectAllCheckbox.addEventListener("change", function () {
			var checkboxes = multiselectDropdown.querySelectorAll('input[type="checkbox"]');
			checkboxes.forEach(function (checkbox) {
				checkbox.checked = selectAllCheckbox.checked;
			});
			moSamlWhitelistRolesUpdateSearchBoxValue();
		});



		searchBox.addEventListener("input", function () {
			var searchValue = this.value.toLowerCase();
			moSamlWhitelistRolesPerformSearch(searchValue);
			moSamlWhitelistRolesUpdateCheckboxes();
		});



		var dropdownCheckboxes = multiselectDropdown.querySelectorAll('input[type="checkbox"]');
		dropdownCheckboxes.forEach(function (checkbox) {
			checkbox.addEventListener("change", function () {
				var allChecked = true;
				dropdownCheckboxes.forEach(function (cb) {
					if (!cb.checked) {
						allChecked = false;
					}
				});
				selectAllCheckbox.checked = allChecked;
				moSamlWhitelistRolesUpdateSearchBoxValue();
			});
		});

		moSamlWhitelistRolesToggleSearchBox();
	}

	$(document).on('click', '.mo-saml-remove-button', function () {
		removeRow(this);
	});

	$(document).on('click', '.mo-saml-add-environment-btn', function () {
		add_environment(this);
	});

	function moSamlWhitelistRolesShowDropdown() {
		var multiselectOptions = document.querySelector("#mo_saml_whitelist_roles_multiselect_dropdown");
		if (multiselectOptions) {
			multiselectOptions.classList.add("mo-saml-whitelist-roles-dropdown-open");
		}
	}

	function moSamlWhitelistRolesHideDropdown() {
		var multiselectOptions = document.querySelector("#mo_saml_whitelist_roles_multiselect_dropdown");
		if (multiselectOptions && multiselectOptions.classList.contains("mo-saml-whitelist-roles-dropdown-open")) {
			multiselectOptions.classList.remove("mo-saml-whitelist-roles-dropdown-open");
		}
	}

	function moSamlWhitelistRolesToggleSearchBox() {
		searchBox.disabled = !enableWhitelistingUsersRoles.checked;
	}

	function moSamlWhitelistRolesUpdateSearchBoxValue() {
		var selectedRoles = [];
		var checkedCheckboxes = multiselectDropdown.querySelectorAll('input[type="checkbox"]:checked');
		checkedCheckboxes.forEach(function (checkbox) {
			if (checkbox !== selectAllCheckbox) {
				selectedRoles.push(checkbox.value);
			}
		});
		searchBox.value = selectedRoles.join(";");
	}

	function moSamlWhitelistRolesFilterDropdownItems(searchValue) {
		var dropdownItems = multiselectDropdown.querySelectorAll('.dropdown-item');
		dropdownItems.forEach(function (item) {
			var optionText = item.textContent.toLowerCase();
			var roleValue = item.querySelector('input[type="checkbox"]').value.toLowerCase();
			if (optionText.includes(searchValue) || whitelistRoles.includes(roleValue)) {
				item.style.display = "block";
			} else {
				item.style.display = "none";
			}
		});
	}

	function moSamlWhitelistRolesPerformSearch(searchValue) {
		var parts = searchValue.split(";");
		parts = parts.map(function (part) {
			return part.trim().toLowerCase();
		});
		parts.forEach(function (part) {
			moSamlWhitelistRolesFilterDropdownItems(part);
		});
	}

	function moSamlWhitelistRolesUpdateCheckboxes() {
		var selectedValues = searchBox.value.trim().toLowerCase().split(";");
		var allCheckboxes = multiselectDropdown.querySelectorAll('input[type="checkbox"]');
		allCheckboxes.forEach(function (checkbox) {
			checkbox.value = checkbox.value.trim().toLowerCase();
			checkbox.checked = selectedValues.includes(checkbox.value);
		});
	}

	var idpGroupAttribute = document.getElementById("mo_saml_rm_group_name");
	jQuery(idpGroupAttribute).on('input change', function () {
		var disabled = true;
		if (idpGroupAttribute.value !== '') {
			disabled = false;
		}
		disableRoleMapping(disabled);
	});

	initializeAttributeMapping();
	initializeRoleMapping();


	preserveEnvironmentInUrls();
	hideViewMoreRoles();
	enableDisabledRoleApplyToAdmin();
	enableDisableAttributeRestriction();
	enableDisableDomainRestriction();
	showHideExistingUserDefaultRole();
	showHideNewUserDefaultRole();

	var input = document.getElementById("contact_us_phone");
	if (input && typeof window.intlTelInput === 'function') {
		window.intlTelInput(input, {
			customPlaceholder: "",
		});
	}

	initializeIdpGrid();

});

function initializeIdpGrid() {
	var gridDiv = document.getElementById('mo_saml_idps_grid_div');
	var allItems = document.querySelectorAll('#mo_saml_idps_grid_div .mosaml-idp-grid-item');

	if (!gridDiv) { return; }

	gridDiv.classList.remove('mosaml-grid-expanded');
	gridDiv.classList.add('mosaml-grid-collapsed');

	var itemsPerRow = 8;
	if (allItems.length > 1) {
		var firstTop = allItems[0].offsetTop;
		itemsPerRow = 0;
		for (var i = 0; i < allItems.length; i++) {
			if (allItems[i].offsetTop !== firstTop) { break; }
			itemsPerRow++;
		}
	}

	for (var i = itemsPerRow; i < allItems.length; i++) {
		allItems[i].style.display = 'none';
		allItems[i].classList.add('mosaml-idp-hidden');
	}
}

function preserveEnvironmentInUrls() {
	var currentUrl = new URL(window.location.href);
	var environment = currentUrl.searchParams.get('environment');

	if (environment) {
		var dropdown = document.getElementById("selectedEnv");
		if (dropdown) {
			for (var i = 0; i < dropdown.options.length; i++) {
				if (dropdown.options[i].value === environment) {
					dropdown.selectedIndex = i;
					break;
				}
			}
		}

		var pluginLinks = document.querySelectorAll('a[href*="page=mo_saml_settings"]');
		pluginLinks.forEach(function (link) {
			var linkUrl = new URL(link.href);
			linkUrl.searchParams.set('environment', environment);
			link.href = linkUrl.toString();
		});
	}
}

function toggleDropdown(id) {
	const dropdown = document.getElementById(id);
	const isVisible = dropdown.style.display === 'block';

	document.querySelectorAll('.mosaml-dropdown-content').forEach(d => d.style.display = 'none');

	if (!isVisible) {
		dropdown.style.display = 'block';

		const handler = function (e) {
			dropdown.style.display = 'none';
			document.removeEventListener('click', handler);
		};
		setTimeout(() => document.addEventListener('click', handler), 0);
	}
}

function makeIdpDefault(idpId) {
	document.getElementById('mosaml_idp_id_to_make_default').value = idpId;
	document.getElementById('idp_form_make_default').submit();
}

function deleteIDP(idpId) {
	document.querySelectorAll('input[name="bulk_action_record[]"]').forEach(function (cb) {
		cb.checked = false;
	});

	const targetCheckbox = document.querySelector(
		'input[name="bulk_action_record[]"][value="' + idpId + '"]'
	);

	if (targetCheckbox) {
		targetCheckbox.checked = true;
	}

	const actionSelect = document.querySelector('select[name="action"]');
	const actionSelect2 = document.querySelector('select[name="action2"]');

	if (actionSelect) actionSelect.value = 'delete';
	if (actionSelect2) actionSelect2.value = 'delete';

	const doActionBtn = document.getElementById('doaction');
	if (doActionBtn) {
		doActionBtn.click();
	}
}


function testIdpConfiguration(url) {
	window.open(url, "Test Configuration", "scrollbars=1 width=800, height=700");
}

/**
 * Initialize attribute mapping functionality
 */
function initializeAttributeMapping() {
	// Add event listeners for basic attribute dropdowns
	var attributeFields = ['username', 'email', 'first_name', 'last_name', 'nick_name'];

	attributeFields.forEach(function (field) {
		var select = document.querySelector('select[name="mo_saml_am_' + field + '"]');
		if (select) {
			select.addEventListener('change', function () {
				toggleAttributeInput(this, field);
			});
		}
	});

	// Add form submission handler
	var form = document.querySelector('form[name="mo_saml_attribute_mapping_form"]');
	if (form) {
		form.addEventListener('submit', handleAttributeMappingFormSubmit);
	}
}

/**
 * Toggle between dropdown and custom input for attribute fields
 */
function toggleAttributeInput(selectElement, fieldName) {
	var customInputDiv = document.getElementById(fieldName + '_custom_input');
	var customInput = customInputDiv.querySelector('input');

	if (selectElement.value === 'custom') {
		customInputDiv.style.display = 'block';
		customInput.required = selectElement.required;
	} else {
		customInputDiv.style.display = 'none';
		customInput.required = false;
		customInput.value = '';
	}
}

/**
 * Handle form submission to use custom values when selected
 */
function handleAttributeMappingFormSubmit(e) {
	// Handle basic attributes
	var attributeFields = ['username', 'email', 'first_name', 'last_name', 'nick_name'];

	attributeFields.forEach(function (field) {
		var select = document.querySelector('select[name="mo_saml_am_' + field + '"]');
		var customInput = document.querySelector('input[name="mo_saml_am_' + field + '_custom"]');

		if (select && customInput && select.value === 'custom') {
			// Create a hidden input with the original name to submit custom value
			var hiddenInput = document.createElement('input');
			hiddenInput.type = 'hidden';
			hiddenInput.name = 'mo_saml_am_' + field;
			hiddenInput.value = customInput.value;
			e.target.appendChild(hiddenInput);

			// Disable the select to prevent submission
			select.disabled = true;
		}
	});

	// Custom attributes now use simple input fields, no special handling needed
}

/**
 * Remove a custom attribute row
 */
function remove_row(element) {
	element.closest('tr').remove();
}

/**
 * Add custom attribute function with dynamic input/dropdown creation
 */
function add_custom_attribute(testAttributes) {
	// Ensure testAttributes is always an array (e.g. when passed from PHP)
	if (!Array.isArray(testAttributes)) {
		testAttributes = [];
	}

	// Find the correct table - the one that contains the save_config_element
	var saveElement = document.getElementById('save_config_element');
	if (!saveElement) {
		console.error('Could not find save_config_element');
		return;
	}

	var table = saveElement.closest('table').querySelector('tbody');
	if (!table) {
		console.error('Could not find table body');
		return;
	}

	var rowCount = table.querySelectorAll('.custom-attr-rows').length;

	var newRow = document.createElement('tr');
	newRow.className = 'custom-attr-rows';

	var attributeInputHtml = '';
	if (testAttributes.length > 0) {
		attributeInputHtml = '<select name="mo_saml_custom_attr_values[]" class="mosaml-width-100">';
		attributeInputHtml += '<option value="">-- Select IDP Attribute --</option>';
		testAttributes.forEach(function (attr) {
			attributeInputHtml += '<option value="' + attr + '">' + attr + '</option>';
		});
		attributeInputHtml += '</select>';
	} else {
		attributeInputHtml = '<input type="text" name="mo_saml_custom_attr_values[]" placeholder="Enter IDP attribute name" class="mosaml-width-100" value="">';
	}

	newRow.innerHTML = '<td>' +
		'<input type="text" class="mosaml-width-100" name="mo_saml_custom_attr_keys[]" placeholder="Custom attribute name" value="">' +
		'</td>' +
		'<td class="mo-saml-padding-left-10px">' + attributeInputHtml + '</td>' +
		'<td class="mosaml-text-align-center">' +
		'<label class="switch mo-saml-toggle-label">' +
		'<input type="checkbox" name="mo_saml_show_custom_attrs[]" value="' + rowCount + '">' +
		'<span class="slider round"></span>' +
		'</label>' +
		'</td>' +
		'<td class="mo-saml-padding-left-10px">' +
		'<input type="button" value="X" onclick="remove_row(this);" class="button button-primary button-large">' +
		'</td>';

	table.insertBefore(newRow, saveElement);
}


/**
 * Initialize role mapping functionality
 */
function initializeRoleMapping() {
	const updateExistingCheckbox = document.getElementById('mo_saml_update_existing_user');
	const existingRoleSelect = document.getElementById('mo_saml_default_role_existing');

	if (updateExistingCheckbox && existingRoleSelect) {
		updateExistingCheckbox.addEventListener('change', function () {
			existingRoleSelect.disabled = !this.checked;
		});
	}
}

function removeRow(button) {
	var row = button.closest('tr');
	if (row) {
		row.remove();
	}
}

function add_environment(button) {
	var table = button.closest('form').querySelector('table');

	var newRow = document.createElement('tr');
	newRow.className = 'rows mo-saml-environment-row';

	var nameCell = document.createElement('td');
	var nameInput = document.createElement('input');
	nameInput.type = 'text';
	nameInput.className = 'row_environment_name mo-saml-environment-name-input';
	nameInput.name = 'mo_saml_environment_names[]';
	nameInput.placeholder = 'Example: Prod, Staging, etc';
	nameInput.pattern = '^\\w*$';
	nameInput.title = 'Only alphabets, numbers and underscore is allowed';
	nameCell.appendChild(nameInput);

	var urlCell = document.createElement('td');
	var urlInput = document.createElement('input');
	urlInput.type = 'url';
	urlInput.name = 'mo_saml_environment_urls[]';
	urlInput.className = 'row_environment_url mo-saml-environment-url-input';
	urlInput.placeholder = 'Example: https://example.com';
	urlCell.appendChild(urlInput);

	var actionCell = document.createElement('td');
	var removeButton = document.createElement('input');
	removeButton.type = 'button';
	removeButton.value = 'X';
	removeButton.className = 'button button-primary button-large mo-saml-remove-button';

	removeButton.addEventListener('click', function () {
		removeRow(this);
	});

	actionCell.appendChild(removeButton);

	newRow.appendChild(nameCell);
	newRow.appendChild(urlCell);
	newRow.appendChild(actionCell);

	var existingRows = table.querySelectorAll('tr.rows');
	if (existingRows.length > 0) {
		var lastRow = existingRows[existingRows.length - 1];
		lastRow.parentNode.insertBefore(newRow, lastRow.nextSibling);
	} else {
		var headerRow = table.querySelector('tr');
		if (headerRow) {
			headerRow.parentNode.insertBefore(newRow, headerRow.nextSibling);
		} else {
			table.appendChild(newRow);
		}
	}
}
function showHideExistingUserDefaultRole() {
	var updateExistingUser = document.getElementById("mo_saml_update_existing_user_with_role");
	jQuery(updateExistingUser).change(function () {
		var defaultRoleInput = document.getElementById("mo_saml_default_role_existing");
		if (updateExistingUser.checked) {
			defaultRoleInput.disabled = false;
		} else {
			defaultRoleInput.disabled = true;
		}
	});
}

function showHideNewUserDefaultRole() {
	var updateNewUser = document.getElementById("mo_saml_create_new_user_with_role");
	jQuery(updateNewUser).change(function () {
		var defaultRoleInput = document.getElementById("mo_saml_default_role_new");
		if (updateNewUser.checked) {
			defaultRoleInput.disabled = false;
		} else {
			defaultRoleInput.disabled = true;
		}
	});
}

function hideViewMoreRoles() {
	jQuery('#mo_saml_view_more_roles').click(function () {
		const roleRows = document.getElementsByClassName("mo-saml-role-row");
		if (roleRows.length === 0) {
			return;
		}
		const viewToggle = document.getElementById("mo_saml_view_more_roles");
		const viewMore = "View More  \u142F";
		const viewLess = "View Less  \u1431";
		for (let i = 0; i < roleRows.length; i++) {
			if (viewToggle.textContent === viewMore) {
				roleRows[i].style.display = "table-row";
			}
			if (i >= 10 && viewToggle.textContent === viewLess) {
				roleRows[i].style.display = "none";
			}
		}
		if (viewToggle.textContent === viewMore) {
			viewToggle.textContent = viewLess;
		} else {
			viewToggle.textContent = viewMore;
		}
	});
}

function disableRoleMapping(disabled) {
	var applyRoleToAdmin = document.getElementById("mo_saml_apply_role_to_admin");
	var rolesInput = document.querySelectorAll('[name^="mo_saml_role_value_"]');
	applyRoleToAdmin.disabled = disabled;
	for (var i = 0; i < rolesInput.length; i++) {
		rolesInput[i].disabled = disabled;
	}
}

function enableDisabledRoleApplyToAdmin() {
	var keepExistingUserRole = document.getElementById("mo_saml_do_not_update_existing_user");
	var applyRoleToAdmin = document.getElementById("mo_saml_apply_role_to_admin");
	jQuery(keepExistingUserRole).change(function () {
		applyRoleToAdmin.disabled = keepExistingUserRole.checked;
	});
}

function showTestWindow(url) {
	var myWindow = window.open(url, "Test Configuration", "scrollbars=1 width=800, height=600");
}

function enableDisableAttributeRestriction() {
	var allowDenyUserAttribute = document.getElementById("mo_saml_allow_deny_idp_attribute_toggle");
	var restrictedAttribute = document.getElementById("mo_saml_attribute_restriction_attr_name");
	var restrictedAttributeValue = document.getElementById("mo_saml_attribute_restriction_attr_value");
	var attributeAllowed = document.getElementById("attribute_allowed");
	var attributeDenied = document.getElementById("attribute_denied");
	jQuery(allowDenyUserAttribute).change(function () {
		if (allowDenyUserAttribute.checked) {
			restrictedAttribute.disabled = false;
			if ('' != restrictedAttribute.value) {
				restrictedAttributeValue.disabled = false;
				attributeAllowed.disabled = false;
				attributeDenied.disabled = false;
			}
		} else {
			restrictedAttribute.disabled = true;
			restrictedAttributeValue.disabled = true;
			attributeAllowed.disabled = true;
			attributeDenied.disabled = true;
		}
	});
	jQuery(restrictedAttribute).on('input change', function () {
		if ('' != restrictedAttribute.value) {
			restrictedAttributeValue.disabled = false;
			attributeAllowed.disabled = false;
			attributeDenied.disabled = false;
		} else {
			restrictedAttributeValue.disabled = true;
			attributeAllowed.disabled = true;
			attributeDenied.disabled = true;
		}
	});
}

function enableDisableDomainRestriction() {
	var allowDenyUserDomain = document.getElementById("mo_saml_allow_deny_user_domain_toggle");
	var configuredDomains = document.getElementById("mo_saml_allow_deny_user_domain_value");
	var domainAllowed = document.getElementById("domain_allowed");
	var domainDenied = document.getElementById("domain_denied");
	jQuery(allowDenyUserDomain).change(function () {
		configuredDomains.disabled = !allowDenyUserDomain.checked;
		domainAllowed.disabled = !allowDenyUserDomain.checked;
		domainDenied.disabled = !allowDenyUserDomain.checked;
	});
}

function toggleIdpGrid() {
	var gridDiv = document.getElementById('mo_saml_idps_grid_div');
	var allItems = document.querySelectorAll('#mo_saml_idps_grid_div .mosaml-idp-grid-item');
	var showMoreBtn = document.getElementById('mosaml-show-more-idps');

	if (!gridDiv || !showMoreBtn) { return; }

	var itemsPerRow = 8;
	if (allItems.length > 1) {
		var firstTop = allItems[0].offsetTop;
		itemsPerRow = 0;
		for (var i = 0; i < allItems.length; i++) {
			if (allItems[i].offsetTop !== firstTop) { break; }
			itemsPerRow++;
		}
	}

	var isExpanded = gridDiv.classList.contains('mosaml-grid-expanded');

	if (isExpanded) {
		for (var i = itemsPerRow; i < allItems.length; i++) {
			allItems[i].style.display = 'none';
			allItems[i].classList.add('mosaml-idp-hidden');
		}
		gridDiv.classList.remove('mosaml-grid-expanded');
		gridDiv.classList.add('mosaml-grid-collapsed');
		showMoreBtn.innerHTML = 'Show More ▼';
	} else {
		for (var i = itemsPerRow; i < allItems.length; i++) {
			allItems[i].style.display = 'inline-block';
			allItems[i].classList.remove('mosaml-idp-hidden');
		}
		gridDiv.classList.remove('mosaml-grid-collapsed');
		gridDiv.classList.add('mosaml-grid-expanded');
		showMoreBtn.innerHTML = 'Show Less ▲';
	}
}

function submitResetConfiguration(name, idp) {
	const parts = name.split("_");
	const lastTwo = parts.slice(-2);
	const capitalized = lastTwo.map(p => p.charAt(0).toUpperCase() + p.slice(1)).join(" ");

	mosaml_showModal({
		title: 'Confirm Reset',
		message: 'Are you sure you want to reset the ' + capitalized + ' configurations for ' + idp + '?',
		buttons: {
			'reset': 'mosaml_submit_reset_form_callback'
		},
		passedVars: { formId: 'mo_saml_reset_' + name }
	});
}

function mosaml_submit_reset_form_callback(vars) {
	if (vars.formId) {
		document.getElementById(vars.formId).submit();
	}
}

function mo_saml_free_up_license_key() {
	document.getElementById("mo_saml_remove_account_form").submit();
}

function confirmlicenseform() {
	jQuery("#mo_saml_sync_license_form").submit();
}

function ChangeSelectedIDP(e) {
	const idp_id = e.target.value;
	const url = new URL(window.location.href);
	url.searchParams.set('idp', idp_id);
	window.location.href = url.toString();
}

function editEnvironmentModal(environmentId, environmentName, environmentUrl, currentEnvironment) {
	console.log('currentEnvironment: ' + currentEnvironment);
	console.log('return value: ' + (currentEnvironment == 1));
	if (environmentId && environmentName && environmentUrl) {
		document.getElementById("mosaml_edit_environment_name").value = environmentName;
		document.getElementById("mosaml_edit_environment_url").value = environmentUrl;
		document.getElementById("mosaml_environment_id").value = environmentId;
	}

	document.getElementById("mosaml_environment_modal").style.display = "block";
	document.getElementById("edit_environment_form").style.display = "block";
	document.getElementById("add_environment_form").style.display = "none";
	document.getElementById("delete_environment_form").style.display = "none";
	document.getElementById("mosaml_environment_submit_type").value = "edit";

	const disableEditOptions = !document.getElementById("mosaml_enable_multiple_environments").checked;

	disableDivElements("add_environment_form", true);
	disableDivElements("edit_environment_form", disableEditOptions);
	disableDivElements("delete_environment_form", true);

	document.getElementById("mosaml_edit_environment_url").readOnly = currentEnvironment == 1;
}

function closeEnvironmentModal() {
	document.getElementById("mosaml_environment_modal").style.display = "none";
	document.getElementById("mosaml_environment_data_form").reset();
	document.getElementById("edit_environment_form").style.display = "none";
	document.getElementById("delete_environment_form").style.display = "none";
	document.getElementById("add_environment_form").style.display = "none";

	const idpSection = document.getElementById("mosaml_delete_environment_idp_section");
	const idpListElement = document.getElementById("mosaml_delete_environment_idp_list");
	if (idpSection) {
		idpSection.style.display = "none";
	}
	if (idpListElement) {
		idpListElement.innerHTML = "";
	}
}

function saveEnvironment() {
	document.getElementById("mosaml_environment_data_form").submit();
}

function deleteEnvironmentModal(environmentId, environmentName, currentEnvironment, idpList = []) {
	document.getElementById("mosaml_environment_modal").style.display = "block";
	document.getElementById("edit_environment_form").style.display = "none";
	document.getElementById("delete_environment_form").style.display = "block";
	document.getElementById("add_environment_form").style.display = "none";
	document.getElementById("mosaml_environment_id").value = environmentId;
	document.getElementById("mosaml_delete_environment_name").textContent = environmentName;
	document.getElementById("mosaml_environment_submit_type").value = "delete";

	// Handle IDP list display
	const idpSection = document.getElementById("mosaml_delete_environment_idp_section");
	const idpListElement = document.getElementById("mosaml_delete_environment_idp_list");

	if (idpList && idpList.length > 0) {
		idpSection.style.display = "block";
		idpListElement.innerHTML = "";
		idpList.forEach(function (idpName) {
			const li = document.createElement("li");
			li.textContent = idpName;
			idpListElement.appendChild(li);
		});
	} else {
		idpSection.style.display = "none";
		idpListElement.innerHTML = "";
	}

	const disableDeleteOptions = !document.getElementById("mosaml_enable_multiple_environments").checked;

	disableDivElements("add_environment_form", true);
	disableDivElements("edit_environment_form", true);
	disableDivElements("delete_environment_form", disableDeleteOptions);

	document.getElementById("mosaml_delete_environment_button").disabled = currentEnvironment == 1;
}

function AddNewEnvironmentModal() {
	document.getElementById("mosaml_environment_modal").style.display = "block";
	document.getElementById("add_environment_form").style.display = "block";
	document.getElementById("edit_environment_form").style.display = "none";
	document.getElementById("delete_environment_form").style.display = "none";
	document.getElementById("mosaml_environment_submit_type").value = "add";

	const disableAddOptions = !document.getElementById("mosaml_enable_multiple_environments").checked;

	disableDivElements("add_environment_form", disableAddOptions);
	disableDivElements("edit_environment_form", true);
	disableDivElements("delete_environment_form", true);
}

function disableDivElements(divId, disable = true) {
	const elements = document.querySelectorAll(`#${divId} button, #${divId} input`);
	elements.forEach(el => {
		el.disabled = disable;
	});
}

function submit_form($this) {
	var envId = jQuery("#selectedEnv").val();
	var form = document.getElementById(envId);
	if (form) {
		form.submit();
	}
}

function updateDatabase() {
	document.getElementById("mosaml_update_database_form").submit();
}

function downloadDatabaseUpdateQueries() {
	const textArea = document.querySelector('#mosaml_all_db_update_queries');
	if (!textArea) return;

	let sqlContent = textArea.value.trim();

	sqlContent = sqlContent
		.replace(/\n{3,}/g, '\n\n')
		.replace(/;(\s*);/g, ';');

	const blob = new Blob([sqlContent], { type: 'text/sql' });
	const url = URL.createObjectURL(blob);
	const a = document.createElement('a');
	a.href = url;
	a.download = 'mosaml-database-queries.sql';
	a.click();
	URL.revokeObjectURL(url);
}

function setupDatabase() {
	document.getElementById("mosaml_setup_database_form").submit();
}
