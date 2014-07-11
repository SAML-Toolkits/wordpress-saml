<?php

    require_once plugin_dir_path(__FILE__).'_toolkit_loader.php';
    require plugin_dir_path(__FILE__).'settings.php';

	$auth = new Onelogin_Saml2_Auth($settings);
	$settings = $auth->getSettings();
	$metadata = $settings->getSPMetadata();
	
	header('Content-Type: text/xml');
	echo $metadata;
