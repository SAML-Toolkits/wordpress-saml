<?php

require_once dirname(dirname(dirname(dirname(__FILE__)))) . '/wp-load.php';
require_once plugin_dir_path(__FILE__)."php/functions.php";
require_once plugin_dir_path(__FILE__)."php/configuration.php";

saml_acs();