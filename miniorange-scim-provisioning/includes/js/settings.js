// jQuery(document).ready(function () {	
// 	//show and hide attribute mapping instructions
//     jQuery("#toggle_am_content").click(function () {
//         jQuery("#show_am_content").toggle();
//     });
// 	jQuery("#scim_test").change(function() {
// 		if(jQuery(this).is(":checked")) {
// 			jQuery("#pr_am_default_user_role").attr('disabled', true);
// 		} else {
// 			jQuery("#pr_am_default_user_role").attr('disabled', false);
// 		}
// 	});
//     if(jQuery("#dont_allow_unlisted_user_role").is(":checked")) {
// 			jQuery("#pr_am_default_user_role").attr('disabled', true);
// 		} else if(!jQuery("#dont_allow_unlisted_user_role").is(":disabled")){
// 			jQuery("#pr_am_default_user_role").attr('disabled', false);
// 		}

// 	jQuery("#dont_create_user_if_role_not_mapped").change(function() {
// 		if(jQuery(this).is(":checked")) {
// 			jQuery("#dont_allow_unlisted_user_role").attr('disabled', true);
// 			jQuery("#pr_am_default_user_role").attr('disabled', true);
// 		} else {
// 			jQuery("#dont_allow_unlisted_user_role").attr('disabled', false);
// 			jQuery("#pr_am_default_user_role").attr('disabled', false);
// 		}
// 	});
//     if(jQuery("#dont_create_user_if_role_not_mapped").is(":checked")) {
// 			jQuery("#dont_allow_unlisted_user_role").attr('disabled', true);
// 			jQuery("#pr_am_default_user_role").attr('disabled', true);
// 		} else if(!jQuery("#dont_allow_unlisted_user_role").is(":disabled")){
// 			//jQuery("#dont_allow_unlisted_user_role").attr('disabled', false);
// 			//jQuery("#pr_am_default_user_role").attr('disabled', false);
// 		}

// 	/*
// 	 * Help & Troubleshooting
// 	 */

// 	//Enable cURL
// 	jQuery("#help_curl_enable_title").click(function () {
//         jQuery("#help_curl_enable_desc").slideToggle(400);
//     });

// 	//enable openssl
// 	jQuery("#help_openssl_enable_title").click(function () {
//         jQuery("#help_openssl_enable_desc").slideToggle(400);
//     });	

// 	//Widget steps
// 	jQuery("#help_widget_steps_title").click(function () {
//         jQuery("#help_widget_steps_desc").slideToggle(400);
//     });

// 	//redirect to idp
// 	jQuery("#redirect_to_idp").click(function (e) {
// 		e.preventDefault;
//         jQuery("#redirect_to_idp_desc").slideToggle(400);
//     });

// 	//redirect to idp
// 	jQuery("#force_authentication_with_idp").click(function (e) {
// 		e.preventDefault;
//         jQuery("#force_authentication_with_idp_desc").slideToggle(400);
//     });

// 	//redirect to idp
// 	jQuery("#registered_only_access").click(function (e) {
// 		e.preventDefault;
//         jQuery("#registered_only_access_desc").slideToggle(400);
//     });

// 	 //Instructions
// 	 jQuery("#help_steps_title").click(function () {
//         jQuery("#help_steps_desc").slideToggle(400);
//     });

// 	//Working of plugin
// 	 jQuery("#help_working_title1").click(function () {
// 		 jQuery("#help_working_desc2").hide();
//         jQuery("#help_working_desc1").slideToggle(400);
//     });

// 	 jQuery("#help_working_title2").click(function () {
// 		   jQuery("#help_working_desc1").hide();
// 	        jQuery("#help_working_desc2").slideToggle(400);
// 	    });

// 	//What is pr
// 	 jQuery("#help_pr_title").click(function () {
//         jQuery("#help_pr_desc").slideToggle(400);
//     });

// 	//pr flows
// 	 jQuery("#help_pr_flow_title").click(function () {
//         jQuery("#help_pr_flow_desc").slideToggle(400);
//     });

// 	//FAQ - certificate
// 	 jQuery("#help_faq_cert_title").click(function () {
//         jQuery("#help_faq_cert_desc").slideToggle(400);
//     });

// 	//FAQ - 404 error
// 	 jQuery("#help_faq_404_title").click(function () {
//         jQuery("#help_faq_404_desc").slideToggle(400);
//     });

// 	//FAQ - idp not configured properly issue
// 	 jQuery("#help_faq_idp_config_title").click(function () {
//         jQuery("#help_faq_idp_config_desc").slideToggle(400);
//     });

// 	//FAQ - redirect to idp issue
// 	 jQuery("#help_faq_idp_redirect_title").click(function () {
//         jQuery("#help_faq_idp_redirect_desc").slideToggle(400);
//     });

// 	//SYNC Metdata
// 	jQuery("#sync_metadata").click(function () {
//         jQuery("#select_time_sync_metadata").slideToggle(400);
//     });


// });

function getlicensekeysform() {
    jQuery("#loginform").submit();
}

