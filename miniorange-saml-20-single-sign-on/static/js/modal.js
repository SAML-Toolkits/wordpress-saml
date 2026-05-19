function mosaml_closeModal() {
	const modal = document.getElementById('mosaml-notice-modal');
	if (modal) {
		modal.classList.remove('active');
	}
}

function mosaml_showModal(options = {}) {
	const modal = document.getElementById('mosaml-notice-modal');
	if (!modal) {
		console.error('Modal element not found');
		return;
	}

	const title = options.title || 'Notice';
	const message = options.message || '';
	const image = options.image || '';
	const buttons = options.buttons || {};
	const passedVars = options.passedVars || {};
	const cancelBtnText = options.cancelBtn || 'Cancel';

	const titleEl = modal.querySelector('.mosaml-notice-modal-title');
	const messageEl = modal.querySelector('.mosaml-notice-modal-message');
	const imageEl = modal.querySelector('.mosaml-notice-modal-image');
	const buttonsEl = modal.querySelector('.mosaml-notice-modal-buttons');

	titleEl.textContent = title;
	messageEl.innerHTML = message;

	if (image) {
		imageEl.innerHTML = '<img src="' + image + '" alt="Modal icon">';
	} else {
		imageEl.innerHTML = '';
	}

	buttonsEl.innerHTML = '';

	for (const buttonLabel in buttons) {
		if (buttons.hasOwnProperty(buttonLabel)) {
			const buttonFunction = buttons[buttonLabel];
			const btn = document.createElement('button');
			btn.className = 'mosaml-notice-modal-btn primary';
			btn.textContent = buttonLabel.charAt(0).toUpperCase() + buttonLabel.slice(1);
			btn.dataset.action = buttonFunction;
			btn.dataset.passedVars = JSON.stringify(passedVars);

			btn.addEventListener('click', function (e) {
				e.preventDefault();
				const action = this.getAttribute('data-action');
				const passedVarsStr = this.getAttribute('data-passed-vars');

				try {
					const variables = JSON.parse(passedVarsStr);
					if (typeof window[action] === 'function') {
						window[action](variables);
					} else {
						console.warn('Function ' + action + ' does not exist.');
					}
				} catch (e) {
					console.error('Error parsing passed variables:', e);
				}

				mosaml_closeModal();
			});

			buttonsEl.appendChild(btn);
		}
	}

	const cancelBtn = document.createElement('button');
	cancelBtn.className = 'mosaml-notice-modal-btn cancel';
	cancelBtn.textContent = cancelBtnText;
	cancelBtn.dataset.action = 'cancel';

	cancelBtn.addEventListener('click', function (e) {
		e.preventDefault();
		mosaml_closeModal();
	});

	buttonsEl.appendChild(cancelBtn);

	modal.classList.add('active');
}

document.querySelectorAll('.mosaml-notice-modal-close').forEach(function (btn) {
	btn.addEventListener('click', function () {
		mosaml_closeModal();
	});
});

document.querySelectorAll('.mosaml-notice-modal-btn[data-action="cancel"]').forEach(function (btn) {
	btn.addEventListener('click', function (e) {
		e.preventDefault();
		mosaml_closeModal();
	});
});

document.querySelectorAll('.mosaml-notice-modal-btn:not([data-action="cancel"])').forEach(function (btn) {
	btn.addEventListener('click', function (e) {
		e.preventDefault();
		const action = this.getAttribute('data-action');
		const passedVars = this.getAttribute('data-passed-vars');

		try {
			const variables = JSON.parse(passedVars);
			if (typeof window[action] === 'function') {
				window[action](variables);
			} else {
				console.warn('Function ' + action + ' does not exist.');
			}
		} catch (e) {
			console.error('Error parsing passed variables:', e);
		}

		mosaml_closeModal();
	});
});

window.mosaml_showModal = mosaml_showModal;
window.mosaml_closeModal = mosaml_closeModal;