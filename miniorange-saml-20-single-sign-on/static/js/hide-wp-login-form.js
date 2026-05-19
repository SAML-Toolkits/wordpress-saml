['user_login', 'rememberme', 'wp-submit'].forEach(function (id) {
	var element = document.getElementById(id);
	if (element) {
		var parentP = element.closest('p');
		var userLoginField = document.getElementById('user_login');
		if (parentP && userLoginField && parentP.contains(userLoginField)) {
			var label = document.querySelector('label[for="user_login"]');
			if (label) {
				label.remove();
			}
			userLoginField.remove();
		}
		else {
			element.closest('p').remove();
		}
	}
});

var nav = document.getElementById('nav');
if (nav) {
	nav.remove();
}

var userPass = document.getElementById('user_pass');
if (userPass) {
	var userPassWrap = userPass.closest('.user-pass-wrap');
	if (userPassWrap) {
		userPassWrap.remove();
	}
}