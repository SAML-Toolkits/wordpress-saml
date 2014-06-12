<?php

	require_once(dirname(__FILE__).'/_toolkit_loader.php');
	require(dirname(__FILE__).'/settings.php');

	$auth = new Onelogin_Saml2_Auth($settings);
	$settings = $auth->getSettings();
	$metadata = $settings->getSPMetadata();
	
	header('Content-Type: text/xml');
	echo $metadata;
