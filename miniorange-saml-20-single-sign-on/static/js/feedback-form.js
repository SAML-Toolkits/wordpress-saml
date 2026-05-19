/**
 * Feedback Form JavaScript.
 *
 * @package miniorange-saml-20-single-sign-on
 */

(function ($) {
	'use strict';

	// Rating messages based on selection
	const ratingMessages = {
		1: 'We are sorry to hear that. Please let us know what went wrong.',
		2: 'We are sorry for the inconvenience. Please share your feedback.',
		3: 'Thank you for your feedback. We would love to hear more.',
		4: 'Thank you for your positive feedback!',
		5: 'Thank you for appreciating our work'
	};

	let deactivateUrl = '';

	function interceptDeactivationLinks() {
		$(document).on('click', 'a[href*="action=deactivate"]', function (e) {
			var href = $(this).attr('href');
			if (href && (href.indexOf('miniorange-saml-20-single-sign-on') !== -1 || href.indexOf('mosaml') !== -1)) {
				e.preventDefault();
				e.stopPropagation();
				deactivateUrl = href;
				showFeedbackModal();
				return false;
			}
		});
	}

	function showFeedbackModal() {
		const modal = document.getElementById('mo_saml_feedback_modal');
		if (modal) {
			modal.style.display = 'block';
		}
	}

	function initFeedbackForm() {
		const modal = document.getElementById('mo_saml_feedback_modal');
		if (!modal) {
			return;
		}

		const closeBtn = modal.querySelector('.mo_saml_close');
		if (closeBtn) {
			closeBtn.addEventListener('click', function () {
				skipFeedback();
			});
		}

		window.addEventListener('click', function (event) {
			if (event.target === modal) {
				skipFeedback();
			}
		});

		const radioButtons = document.querySelectorAll('.mo-saml-fb-radio');
		radioButtons.forEach(function (radio) {
			radio.addEventListener('change', function () {
				updateRatingMessage(this.value);
			});
		});

		const editRadio = document.getElementById('edit');
		const emailInput = document.getElementById('query_mail');
		if (editRadio && emailInput) {
			editRadio.addEventListener('change', function () {
				if (this.checked) {
					emailInput.removeAttribute('readonly');
					emailInput.focus();
				}
			});
		}

		const feedbackForm = document.getElementById('mosaml_feedback');
		if (feedbackForm) {
			feedbackForm.addEventListener('submit', function (e) {
				const email = document.getElementById('query_mail').value;
				if (!email || !isValidEmail(email)) {
					e.preventDefault();
					alert('Please enter a valid email address.');
					return false;
				}
			});
		}

		const skipButton = document.querySelector('.mosaml-skip-feedback');
		if (skipButton) {
			skipButton.addEventListener('click', function (e) {
				e.preventDefault();
				skipFeedback();
			});
		}
	}

	function updateRatingMessage(rating) {
		const resultSpan = document.getElementById('result');
		if (resultSpan && ratingMessages[rating]) {
			resultSpan.textContent = ratingMessages[rating];
		}
	}

	function skipFeedback() {
		const skipForm = document.getElementById('mo_saml_feedback_form_close');
		if (skipForm) {
			skipForm.submit();
		} else {
			proceedWithDeactivation();
		}
	}

	function proceedWithDeactivation() {
		if (deactivateUrl) {
			window.location.href = deactivateUrl;
		}
	}

	function isValidEmail(email) {
		const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
		return re.test(email);
	}

	window.editName = function () {
		const emailInput = document.getElementById('query_mail');
		const editRadio = document.getElementById('edit');
		if (emailInput && editRadio) {
			if (editRadio.checked) {
				emailInput.removeAttribute('readonly');
				emailInput.focus();
			} else {
				emailInput.setAttribute('readonly', 'readonly');
			}
		}
	};

	$(document).ready(function () {
		interceptDeactivationLinks();
		initFeedbackForm();
	});

})(jQuery);

