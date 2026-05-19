<?php
/**
 * This file contains the metadata in the XML format to be displayed or downloaded.
 *
 * @package MOSAML
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Echoed here due to XML limitations, will look into a better solution later.
echo '<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="' . esc_attr( gmdate( 'Y-m-d\TH:i:s\Z', $this->certificate_expiry_date ) ) . '" cacheDuration="PT1446808792S" entityID="' . esc_attr( $this->sp_endpoints->sp_entity_id ) . '">
    <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
		' . esc_html( $this->extension_node ) . '' . esc_html( $this->certificate_node ) . '' . esc_html( $this->logout_url_node ) . '
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
		' . esc_html( $this->name_id_format_node ) . '
	    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="' . esc_url( $this->sp_endpoints->sp_base_url ) . '" index="1"/>
    </md:SPSSODescriptor>
	<md:Organization>
		<md:OrganizationName xml:lang="en-US">' . esc_html( $this->sp_organization_details->organization_name ) . '</md:OrganizationName>
		<md:OrganizationDisplayName xml:lang="en-US">' . esc_html( $this->sp_organization_details->organization_display_name ) . '</md:OrganizationDisplayName>
		<md:OrganizationURL xml:lang="en-US">' . esc_html( $this->sp_organization_details->organization_url ) . '</md:OrganizationURL>
	</md:Organization>
	<md:ContactPerson contactType="technical">
		<md:GivenName>' . esc_html( $this->sp_organization_details->technical_person_name ) . '</md:GivenName>
		<md:EmailAddress>' . esc_html( $this->sp_organization_details->technical_person_email ) . '</md:EmailAddress>
	</md:ContactPerson>
	<md:ContactPerson contactType="support">
		<md:GivenName>' . esc_html( $this->sp_organization_details->support_person_name ) . '</md:GivenName> 
		<md:EmailAddress>' . esc_html( $this->sp_organization_details->support_person_email ) . '</md:EmailAddress>
	</md:ContactPerson>
</md:EntityDescriptor>';
exit;
