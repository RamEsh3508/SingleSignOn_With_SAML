namespace AdeNet.Web.Components
{
	internal class SAMLSecondLevelStatusCode
	{
		#region Constants
		/// <summary>
		/// The responding provider was unable to successfully authenticate the principal.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_AUTHNFAILED = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";

		/// <summary>
		/// Unexpected or invalid content was encountered within a &lt;saml:Attribute/&gt; or &lt;saml:AttributeValue/&gt; element.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_INVALIDATTRNAMEORVALUE = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue";

		/// <summary>
		/// The responding provider cannot or will not support the requested name identifier policy.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_INVALIDNAMEIDPOLICY = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy";

		/// <summary>
		/// The specified authentication context requirements cannot be met by the responder.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_NOAUTHNCONTEXT = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext";

		/// <summary>
		/// Used by an intermediary to indicate that none of the supported identity provider <Loc/> elements in an <IDPList/> can be resolved
		/// or that none of the supported identity providers are available.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_NOAVAILABLEIDP = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP";

		/// <summary>
		/// Indicates the responding provider cannot authenticate the principal passively, as has been requested.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_NOPASSIVE = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";

		/// <summary>
		/// Used by an intermediary to indicate that none of the identity providers in an <IDPList/> are supported by the intermediary.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_NOSUPPORTEDIDP = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP";

		/// <summary>
		/// Used by a session authority to indicate to a session participant that it was not able to propagate logout to all other session participants.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_PARTIALLOGOUT = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";

		/// <summary>
		/// Indicates that a responding provider cannot authenticate the principal directly and is not permitted to proxy the request further.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_PROXYCOUNTEXCEEDED = "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded";

		/// <summary>
		/// The SAML responder or SAML authority is able to process the request but has chosen not to respond.
		/// This status code MAY be used when there is concern about the security context of the request message or the sequence of request messages received from a particular requester.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_REQUESTDENIED = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";

		/// <summary>
		/// The SAML responder or SAML authority does not support the request.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_REQUESTUNSUPPORTED = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported";

		/// <summary>
		/// The SAML responder cannot process any requests with the protocol version specified in the request.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_REQUESTVERSIONDEPRECATED = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated";

		/// <summary>
		/// The SAML responder cannot process the request because the protocol version specified in the request message is a major upgrade from the highest protocol version supported by the responder.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_REQUESTVERSIONTOOHIGH = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh";

		/// <summary>
		/// The SAML responder cannot process the request because the protocol version specified in the request message is too low.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_REQUESTVERSIONTOOLOW = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow";

		/// <summary>
		/// The resource value provided in the request message is invalid or unrecognized.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_RESOURCENOTRECOGNIZED = "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized";

		/// <summary>
		/// The response message would contain more elements than the SAML responder is able to return.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_TOOMANYRESPONSES = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses";

		/// <summary>
		/// An entity that has no knowledge of a particular attribute profile has been presented with an attribute drawn from that profile.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_UNKNOWNATTRPROFILE = "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile";

		/// <summary>
		/// The responding provider does not recognize the principal specified or implied by the request.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_UNKNOWNPRINCIPAL = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal";

		/// <summary>
		/// The SAML responder cannot properly fulfill the request using the protocol binding specified in the request.
		/// </summary>
		internal const string SAML_SECONDLEVEL_STATUSCODE_UNSUPPORTEDBINDING = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding";
		#endregion
	}
}