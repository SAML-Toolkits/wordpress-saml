<?php

if (!function_exists('wp_roles'))
{
    function wp_roles() {
        global $wp_roles;
     
        if ( ! isset( $wp_roles ) ) {
            $wp_roles = new WP_Roles();
        }
        return $wp_roles;
    }
}