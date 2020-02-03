using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Web;
using System.Xml;
using System.Xml.Linq;

namespace AdeNet.Web.Components
{
	internal class SAMLIdentityProvider
	{
		#region Constants
		internal static readonly XNamespace SAML_PROTOCOL_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:protocol";
		internal static readonly XNamespace SAML_ASSERTION_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion";
	    internal const string SAML_ASSERTION_AUTHNCONTEXTCLASSREF = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
        internal const string SAML_ASSERTION_SUBJECT_NAMEID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
	    internal const string SAML_ASSERTION_SUBJECT_CONFIRMATION_METHOD = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
		internal const string SAML_PROTOCOL_NAMESPACE_PREFIX = "saml2p";
		private const string SAML_ASSERTION_NAMESPACE_PREFIX = "saml2";
		private const string STATUS_ELEMENT_NAME = "Status";
		private const string SAML_VERSION = "2.0";
		internal const string GIVEN_NAME_ASSERTION_ATTRIBUTE_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname";
		internal const string SURNAME_ASSERTION_ATTRIBUTE_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname";
		internal const string NAME_ASSERTION_ATTRIBUTE_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
		internal const string EMAIL_ADDRESS_ASSERTION_ATTRIBUTE_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
		internal const string COMPANY_SUBNR_ASSERTION_ATTRIBUTE_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";
		internal const string SPCD_ASSERTION_ATTRIBUTE_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/locality";
		#endregion

		#region Fields
		private static ISAMLCertificateManager s_samlCertificateManager;
		#endregion

		#region Properties
		internal ISAMLCertificateManager SAMLCertificateManager
		{
			get { return s_samlCertificateManager ?? (s_samlCertificateManager = new SAMLCertificateManager()); }
			set { s_samlCertificateManager = value; }
		}
		#endregion

		#region Internals
		internal SAMLAuthnResponse CreateResponse(SAMLAuthnRequest request, params SAMLAssertionAttribute[] additionalAttributes)
		{
			if(request == null) throw new ArgumentNullException("request");

			/* Extracting AuthnRequest values */
			// Convert request string to xml-format
			XDocument samlXmlDocument = XDocument.Parse(request.SAMLRequest);
			XElement elementRequest = samlXmlDocument.Element(SAML_PROTOCOL_NAMESPACE + "AuthnRequest");
			if(elementRequest == null) throw new InvalidOperationException("Missing root element 'AuthnRequest'.");

			// Extract element and attribute values
			string strRequestID = (string) elementRequest.Attribute("ID");
			string strVersion = (string) elementRequest.Attribute("Version");
			string strDestination = (string) elementRequest.Attribute("Destination");
			string strIssuer = (string) elementRequest.Element(SAML_ASSERTION_NAMESPACE + "Issuer");
			
			/* Checking AuthnRequest values */
			// Check ID Attribute
			if(string.IsNullOrWhiteSpace(strRequestID))
			{
				throw new InvalidOperationException("Attribute 'ID' of the <AuthnRequest/> element is not present.");
			}

			// Check Request Method
			if(request.HttpMethod != "POST")
			{
				// Only POST requests are accepted
				string strStatusMessage = string.Format("SAMLAuthnRequest was made via HttpMethod '{0}' when only HttpMethod 'POST' is supported.", request.HttpMethod);
				return CreateFailureResponse(request, strRequestID, strIssuer, SAMLTopLevelStatusCode.SAML_TOPLEVEL_STATUSCODE_REQUESTER, strStatusMessage,
				                             SAMLSecondLevelStatusCode.SAML_SECONDLEVEL_STATUSCODE_REQUESTUNSUPPORTED);
			}

			// Check Version
			if(strVersion != SAML_VERSION)
			{
				string strStatusMessage = string.Format("Version of SAMLAuthnRequest was '{0}' but only Version '2.0' is supported.", strVersion);
				return CreateFailureResponse(request, strRequestID, strIssuer, SAMLTopLevelStatusCode.SAML_TOPLEVEL_STATUSCODE_VERSION_MISMATCH, strStatusMessage,
				                             SAMLSecondLevelStatusCode.SAML_SECONDLEVEL_STATUSCODE_REQUESTVERSIONDEPRECATED);
			}

			// Check Destination
		    string strSamlServiceLocationURL = SystemSettings<SingleSignOnSystemSettings>.Current.SamlServiceLocationURL;
		    if(string.IsNullOrWhiteSpace(strSamlServiceLocationURL))
		    {
                AdeNetSingleSignOn.Log.Warn("The SamlServiceLocationURL for SingleSignOn on the IdentityProvider is not configured in the systemsettings.");
		    }
            else if(!string.Equals(strDestination, strSamlServiceLocationURL, StringComparison.InvariantCultureIgnoreCase))
			{
                string strStatusMessage = string.Format("SAMLAuthnRequest Destination-Attribute with value '{0}' does not match the configured url in the systemsettings with value '{1}'.", strDestination, SystemSettings<SingleSignOnSystemSettings>.Current.SamlServiceLocationURL);
				return CreateFailureResponse(request, strRequestID, strIssuer, SAMLTopLevelStatusCode.SAML_TOPLEVEL_STATUSCODE_REQUESTER, strStatusMessage,
				                             SAMLSecondLevelStatusCode.SAML_SECONDLEVEL_STATUSCODE_REQUESTUNSUPPORTED);
			}

			// Check Issuer
            if(!SingleSignOnConfiguration.IsRequestIssuerConfigured()) throw new Exception("SAMLAuthnResponse cannot be transmitted because there is no SamlRequestIssuer configured in the systemsettings.");
			ValidateResult resultRequestIssuer = SingleSignOnConfiguration.IsValidRequestIssuer(strIssuer);
			if(!resultRequestIssuer.Valid)
			{
				return CreateFailureResponse(request, strRequestID, strIssuer, SAMLTopLevelStatusCode.SAML_TOPLEVEL_STATUSCODE_REQUESTER, resultRequestIssuer.Message);
			}

			if(UserContext.Current.IsAnonymous)
			{
				// No Single Sign On information found
				return CreateFailureResponse(request,
				                             strRequestID,
											 strIssuer,
				                             SAMLTopLevelStatusCode.SAML_TOPLEVEL_STATUSCODE_RESPONDER,
				                             "SingleSignOn Authentication failed. No user information available from prior user authentication.",
				                             SAMLSecondLevelStatusCode.SAML_SECONDLEVEL_STATUSCODE_AUTHNFAILED);
			}

			// Validate Request Certificate
			ValidateResult result = ValidateAuthnRequest(request);
			if(!result)
			{
				return CreateFailureResponse(request, strRequestID, strIssuer, SAMLTopLevelStatusCode.SAML_TOPLEVEL_STATUSCODE_REQUESTER, result.Message, SAMLSecondLevelStatusCode.SAML_SECONDLEVEL_STATUSCODE_REQUESTDENIED);
			}

			return CreateSuccessResponse(strRequestID, strIssuer, request.RelayState, additionalAttributes);
		}
		#endregion

		#region Privates
		private SAMLAuthnResponse CreateAuthnResponse(string strIssuer, string strResponseString, string strRelayState)
		{
			return new SAMLAuthnResponse
			       {
				       // Response-String with SAML Assertion
				       SAMLResponse = strResponseString,
				       // RelayState as submitted in the AuthnRequest
				       RelayState = strRelayState,
				       // Target URL for the AuthnResponse
				       SAMLAssertionConsumerServiceURL = SingleSignOnConfiguration.GetAssertionConsumerServiceURLByRequestIssuer(strIssuer)
			       };
		}

		private SAMLAuthnResponse CreateSuccessResponse(string strRequestId, string strIssuerURN, string strRelayState, params SAMLAssertionAttribute[] additionalAttributes)
		{
			string strIssueInstantTimeStamp = UserContext.Current.Now.ToUniversalTime().ToString("O");
			string strValidUntilTimeStamp = UserContext.Current.Now.AddMinutes(5).ToUniversalTime().ToString("O");

			XNamespace nsXmlSchema = "http://www.w3.org/2001/XMLSchema";
			XNamespace nsXmlSchemaInstance = "http://www.w3.org/2001/XMLSchema-instance";

			string strAssertionElementName = "Assertion";

			// Response - Root-Element
			XElement elementResponse = CreateResponseElement(strRequestId, strIssuerURN);

			// Response Issuer
			// <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://www.partnerweb.ch/AKXYZ/</saml2:Issuer>
			XElement elementResponseIssuer = new XElement(SAML_ASSERTION_NAMESPACE + "Issuer", SystemSettings<SingleSignOnSystemSettings>.Current.SamlServiceEntityId,
			                                              new XAttribute(XNamespace.Xmlns + SAML_ASSERTION_NAMESPACE_PREFIX, SAML_ASSERTION_NAMESPACE));
			elementResponse.Add(elementResponseIssuer);

			// Status Element
			elementResponse.Add(CreateStatusElement(SAMLTopLevelStatusCode.SAML_TOPLEVEL_STATUSCODE_SUCCESS));

			// Assertion Element
			string strAssertionId = string.Format("{0}_{1}", strAssertionElementName, Guid.NewGuid());
			XElement elementResponseAssertion =
				new XElement(SAML_ASSERTION_NAMESPACE + strAssertionElementName,
				             new XAttribute("ID", strAssertionId),
				             new XAttribute("IssueInstant", strIssueInstantTimeStamp),
				             new XAttribute("Version", "2.0"),
				             new XAttribute(XNamespace.Xmlns + SAML_ASSERTION_NAMESPACE_PREFIX, SAML_ASSERTION_NAMESPACE),
				             new XAttribute(XNamespace.Xmlns + "xs", nsXmlSchema),
				             new XElement(SAML_ASSERTION_NAMESPACE + "Issuer", SystemSettings<SingleSignOnSystemSettings>.Current.SamlServiceEntityId)
					);

			// Subject Element
			XElement elementAssertionSubject =
				new XElement(SAML_ASSERTION_NAMESPACE + "Subject",
				             new XElement(SAML_ASSERTION_NAMESPACE + "NameID", UserContext.Current.Login,
				                          new XAttribute("Format", SAML_ASSERTION_SUBJECT_NAMEID_FORMAT)),
				             new XElement(SAML_ASSERTION_NAMESPACE + "SubjectConfirmation",
				                          new XAttribute("Method", SAML_ASSERTION_SUBJECT_CONFIRMATION_METHOD),
				                          new XElement(SAML_ASSERTION_NAMESPACE + "SubjectConfirmationData",
				                                       new XAttribute("InResponseTo", strRequestId),
				                                       new XAttribute("NotOnOrAfter", strValidUntilTimeStamp),
				                                       new XAttribute("Recipient", SingleSignOnConfiguration.GetAssertionConsumerServiceURLByRequestIssuer(strIssuerURN)))));
			elementResponseAssertion.Add(elementAssertionSubject);

			// Conditions Element
			XElement elementAssertionConditions =
				new XElement(SAML_ASSERTION_NAMESPACE + "Conditions",
				             new XAttribute("NotBefore", strIssueInstantTimeStamp),
				             new XAttribute("NotOnOrAfter", strValidUntilTimeStamp),
				             new XElement(SAML_ASSERTION_NAMESPACE + "AudienceRestriction",
				                          new XElement(SAML_ASSERTION_NAMESPACE + "Audience", strIssuerURN)));
			elementResponseAssertion.Add(elementAssertionConditions);

			// AuthnStatement Element
			XElement elementAssertionAuthnStatement =
				new XElement(SAML_ASSERTION_NAMESPACE + "AuthnStatement",
				             new XAttribute("AuthnInstant", strIssueInstantTimeStamp),
				             new XElement(SAML_ASSERTION_NAMESPACE + "AuthnContext",
				                          new XElement(SAML_ASSERTION_NAMESPACE + "AuthnContextClassRef", SAML_ASSERTION_AUTHNCONTEXTCLASSREF)));
			elementResponseAssertion.Add(elementAssertionAuthnStatement);
			
			// AttributeStatement Element
			XElement elementAssertionAttributeStatement =
				new XElement(SAML_ASSERTION_NAMESPACE + "AttributeStatement",
				             new XElement(SAML_ASSERTION_NAMESPACE + "Attribute",
				                          new XAttribute("Name", GIVEN_NAME_ASSERTION_ATTRIBUTE_NAME),
				                          new XElement(SAML_ASSERTION_NAMESPACE + "AttributeValue", UserContext.Current.FirstName,
				                                       new XAttribute(XNamespace.Xmlns + "xsi", nsXmlSchemaInstance),
				                                       new XAttribute(nsXmlSchemaInstance + "Type", "xs:string")
					                          )
					             ),
				             new XElement(SAML_ASSERTION_NAMESPACE + "Attribute",
				                          new XAttribute("Name", SURNAME_ASSERTION_ATTRIBUTE_NAME),
				                          new XElement(SAML_ASSERTION_NAMESPACE + "AttributeValue", UserContext.Current.LastName,
				                                       new XAttribute(XNamespace.Xmlns + "xsi", nsXmlSchemaInstance),
				                                       new XAttribute(nsXmlSchemaInstance + "Type", "xs:string")
					                          )
					             ),
				             new XElement(SAML_ASSERTION_NAMESPACE + "Attribute",
				                          new XAttribute("Name", NAME_ASSERTION_ATTRIBUTE_NAME),
				                          new XElement(SAML_ASSERTION_NAMESPACE + "AttributeValue", UserContext.Current.Login,
				                                       new XAttribute(XNamespace.Xmlns + "xsi", nsXmlSchemaInstance),
				                                       new XAttribute(nsXmlSchemaInstance + "Type", "xs:string")
					                          )
					             ),
				             new XElement(SAML_ASSERTION_NAMESPACE + "Attribute",
				                          new XAttribute("Name", EMAIL_ADDRESS_ASSERTION_ATTRIBUTE_NAME),
				                          new XElement(SAML_ASSERTION_NAMESPACE + "AttributeValue", UserContext.Current.EMail,
				                                       new XAttribute(XNamespace.Xmlns + "xsi", nsXmlSchemaInstance),
				                                       new XAttribute(nsXmlSchemaInstance + "Type", "xs:string")
					                          )
					             ),
							new XElement(SAML_ASSERTION_NAMESPACE + "Attribute",
										  new XAttribute("Name", COMPANY_SUBNR_ASSERTION_ATTRIBUTE_NAME),
										  new XElement(SAML_ASSERTION_NAMESPACE + "AttributeValue", UserContext.Current.CompanySubNr,
													   new XAttribute(XNamespace.Xmlns + "xsi", nsXmlSchemaInstance),
													   new XAttribute(nsXmlSchemaInstance + "Type", "xs:string")
											  )
								 ),
							new XElement(SAML_ASSERTION_NAMESPACE + "Attribute",
										  new XAttribute("Name", SPCD_ASSERTION_ATTRIBUTE_NAME),
										  new XElement(SAML_ASSERTION_NAMESPACE + "AttributeValue", UserContext.Current.SpCd,
													   new XAttribute(XNamespace.Xmlns + "xsi", nsXmlSchemaInstance),
													   new XAttribute(nsXmlSchemaInstance + "Type", "xs:string")
											  )
								 )
					);

			if(additionalAttributes != null)
			{
				// Add Attributes to the <AttributeStatement /> element
				foreach(SAMLAssertionAttribute samlAssertionAttribute in additionalAttributes)
				{
					elementAssertionAttributeStatement.Add(
					                                       new XElement(SAML_ASSERTION_NAMESPACE + "Attribute",
					                                                    new XAttribute("Name", samlAssertionAttribute.Name),
					                                                    new XElement(SAML_ASSERTION_NAMESPACE + "AttributeValue", samlAssertionAttribute.Value,
					                                                                 new XAttribute(XNamespace.Xmlns + "xsi", nsXmlSchemaInstance),
					                                                                 new XAttribute(nsXmlSchemaInstance + "Type", "xs:string")
						                                                    )
						                                       )
						);
				}
			}

			// Add AttributeStatement Element to Assertion Element
			elementResponseAssertion.Add(elementAssertionAttributeStatement);

			// Add Assertion Element to the Response Element
			elementResponse.Add(elementResponseAssertion);

			// Create Response
			XDocument samlResponseXml = new XDocument(elementResponse);

			// Sign Assertion Element
			string strSignedXmlResponseString = CreateSignedDocumentString(samlResponseXml, strAssertionElementName, SAML_ASSERTION_NAMESPACE_PREFIX, SAML_ASSERTION_NAMESPACE.NamespaceName,
			                                                               "#" + strAssertionId);
			return CreateAuthnResponse(strIssuerURN, strSignedXmlResponseString, strRelayState);
		}

	    private XElement CreateResponseElement(string strRequestId, string strIssuerURN)
		{
			string strIssueInstantTimeStamp = UserContext.Current.Now.ToUniversalTime().ToString("O");

            /* <saml2p:Response Destination="https://feds.eiam.admin.ch/adfs/ls/"
             *					ID="Response_f21ccc44a172149d99dce0b83b059918808bf460"
             *					InResponseTo="id-6250a3ec-0a4a-4305-ab59-6397c0d93da4"
             *					IssueInstant="2015-01-12T17:34:26.875Z"
             *					Version="2.0"
             *					xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"> */

			return new XElement(SAML_PROTOCOL_NAMESPACE + "Response",
                                new XAttribute("Destination", SingleSignOnConfiguration.GetAssertionConsumerServiceURLByRequestIssuer(strIssuerURN)),
			                    new XAttribute("ID", string.Format("Response_{0}", Guid.NewGuid())),
			                    new XAttribute("InResponseTo", strRequestId),
			                    new XAttribute("IssueInstant", strIssueInstantTimeStamp),
			                    new XAttribute("Version", "2.0"),
			                    new XAttribute(XNamespace.Xmlns + SAML_PROTOCOL_NAMESPACE_PREFIX, SAML_PROTOCOL_NAMESPACE));
		}

		private XElement CreateStatusElement(string topLevelSamlTopLevelStatusCode, params string[] secondLevelSAMLStatusCodes)
		{
			return CreateStatusElement(topLevelSamlTopLevelStatusCode, string.Empty, secondLevelSAMLStatusCodes);
		}

		private XElement CreateStatusElement(string strTopLevelSamlTopLevelStatusCode, string strStatusMessage, params string[] strSecondLevelSAMLStatusCodes)
		{
			/* <saml2p:Status>
			 *		<saml2p:StatusCode Value="urn:oa-sis:names:tc:SAML:2.0:status:Success" />
			 *		<saml2p:StatusMessage>AUTH_success</samlp:StatusMessage>
			 *	</saml2p:Status> */

			XElement elementStatus = new XElement(SAML_PROTOCOL_NAMESPACE + "Status");
			XElement elementTopLevelStatusCode = CreateStatusCodeElement(strTopLevelSamlTopLevelStatusCode);

			if(!string.IsNullOrWhiteSpace(strStatusMessage))
			{
				// add optional <StatusMessage /> element
				elementStatus.Add(new XElement(SAML_PROTOCOL_NAMESPACE + "StatusMessage", strStatusMessage));
			}

			if(strSecondLevelSAMLStatusCodes != null && strSecondLevelSAMLStatusCodes.Length > 0)
			{
				// Nested StatusCode elements can be added to provide more information about the error
				foreach(string secondLevelSamlStatusCode in strSecondLevelSAMLStatusCodes)
				{
					/* <samlp:Status>
					 *		<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">
					 *			<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" />
					 *		</samlp:StatusCode>
					 *	</samlp:Status> */

					elementTopLevelStatusCode.Add(CreateStatusCodeElement(secondLevelSamlStatusCode));
				}
			}

			elementStatus.Add(elementTopLevelStatusCode);
			return elementStatus;
		}

		private XElement CreateStatusCodeElement(string strSamlStatusCode)
		{
			// <saml2p:StatusCode Value="urn:oa-sis:names:tc:SAML:2.0:status:Success" />
			return new XElement(SAML_PROTOCOL_NAMESPACE + "StatusCode", new XAttribute("Value", strSamlStatusCode));
		}

		private string CreateSignedDocumentString(XDocument samlResponseXml, string strElementToSign, string strNamespacePrefix, string strNamespaceURI, string strReferenceURI)
		{
			X509Certificate2 certificate = this.SAMLCertificateManager.GetAuthnResponseCertificate();

			string strXPathExpression = string.Format("//{0}:{1}", strNamespacePrefix, strElementToSign);
			XmlNamespaceManager nsMgr = new XmlNamespaceManager(new NameTable());
			nsMgr.AddNamespace(strNamespacePrefix, strNamespaceURI);

			XmlDocument xmlDocumentSignedAssertion = new XmlDocument();
			xmlDocumentSignedAssertion.LoadXml(samlResponseXml.ToString());
			XmlElement xmlElemenResponseAssertion = xmlDocumentSignedAssertion.SelectSingleNode(strXPathExpression, nsMgr) as XmlElement;
			if(xmlElemenResponseAssertion == null) throw new Exception(string.Format("Error signing AuthnResponse. Element <{0}:{1} xmlns:{0}=\"{2}\" /> was not found.", strNamespacePrefix, strElementToSign, strNamespacePrefix));
			SignedXml signedAssertionXml = new SignedXml(xmlElemenResponseAssertion);
			signedAssertionXml.SigningKey = certificate.PrivateKey;
			signedAssertionXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

			// Add Reference to Request-ID
			Reference reference = new Reference(strReferenceURI);
			reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
			reference.AddTransform(new XmlDsigExcC14NTransform("xs"));
			signedAssertionXml.AddReference(reference);

			// Add <KeyInfo> to the XML signature
			KeyInfo keyInfo = new KeyInfo();
			KeyInfoX509Data keyInfoData = new KeyInfoX509Data(certificate);
			keyInfo.AddClause(keyInfoData);
			signedAssertionXml.KeyInfo = keyInfo;

			// Compute Signature Value
			signedAssertionXml.ComputeSignature();

            // Get Issuer Element
		    XmlElement xmlElementResponseAssertionIssuer = xmlElemenResponseAssertion.FirstChild as XmlElement;
            if(xmlElementResponseAssertionIssuer == null) throw new Exception("Error signing AuthnResponse. Element Issuer was not found.");

			// Append <Signature> to the XML
			XmlElement elementSignature = signedAssertionXml.GetXml();
			xmlElemenResponseAssertion.InsertAfter(elementSignature, xmlElementResponseAssertionIssuer);

			return xmlDocumentSignedAssertion.OuterXml;
		}

		private SAMLAuthnResponse CreateFailureResponse(SAMLAuthnRequest request, string strRequestId, string strIssuerURN, string strTopLevelSamlTopLevelStatusCode, string strStatusMessage,
		                                                params string[] strSecondLevelSAMLStatusCodes)
		{
			// Response - Root-Element
			XElement elementResponse = CreateResponseElement(strRequestId, strIssuerURN);

            // Issuer Element
		    elementResponse.Add(
		                        new XElement(SAML_ASSERTION_NAMESPACE + "Issuer", SystemSettings<SingleSignOnSystemSettings>.Current.SamlServiceEntityId,
		                                     new XAttribute(XNamespace.Xmlns + SAML_ASSERTION_NAMESPACE_PREFIX, SAML_ASSERTION_NAMESPACE)));

			// Status Element
			elementResponse.Add(CreateStatusElement(strTopLevelSamlTopLevelStatusCode, strStatusMessage, strSecondLevelSAMLStatusCodes));

			// Create Response
			XDocument samlResponseXml = new XDocument(elementResponse);

			// Sign Assertion Element
			string strSignedXmlResponseString = CreateSignedDocumentString(samlResponseXml, STATUS_ELEMENT_NAME, SAML_PROTOCOL_NAMESPACE_PREFIX, SAML_PROTOCOL_NAMESPACE.NamespaceName, "");
			SAMLAuthnResponse response = CreateAuthnResponse(strIssuerURN, strSignedXmlResponseString, request.RelayState);

			// Log the Error
			AdeNetSingleSignOn.Log.Error(strStatusMessage, strRequestId, request, response);

			return response;
		}

		private ValidateResult ValidateAuthnRequest(SAMLAuthnRequest request)
		{
			if(request == null) throw new ArgumentNullException("request");

			try
			{
				XmlDocument samlRequest = new XmlDocument();
				samlRequest.LoadXml(request.SAMLRequest);

				XmlNodeList nodesXMLSignatures = samlRequest.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#");

				// Checking If the Response or the Assertion has been signed once and only once.
				if(nodesXMLSignatures.Count != 1) return ValidateResult.Failure(string.Format("Number of <signature> elements in AuthnRequest is invalid. Expected number is 1. Actual number is {0}.", nodesXMLSignatures.Count));

				SignedXml signedSamlXml = new SignedXml(samlRequest);
				signedSamlXml.LoadXml((XmlElement) nodesXMLSignatures[0]);

				// Use KeyInfo-Element (X509Data) of the Signature-Element to instantiate the X509Certificate
				KeyInfoX509Data keyInfoData = signedSamlXml.Signature.KeyInfo.OfType<KeyInfoX509Data>().First();
				X509Certificate2 signatureCertificate = keyInfoData.Certificates[0] as X509Certificate2;

				if(!this.SAMLCertificateManager.IsValidAuthnRequestSignature(signedSamlXml, signatureCertificate)) return ValidateResult.Failure("Invalid digital Signature detected.");
				if(!this.SAMLCertificateManager.IsValidAuthnRequestCertificate(signatureCertificate)) return ValidateResult.Failure("Signature-Certificate invalid.");
				if(!this.SAMLCertificateManager.IsAuthorizedAuthnRequestCertificate(signatureCertificate)) return ValidateResult.Failure("Certificate Issuer not authorized for single sign on.");
			}
			catch(Exception ex)
			{
				string strMessage = string.Format("AuthnRequest-Validation failed for user with E-Mail '{0}'. Message: {1}", UserContext.Current.EMail, ex.Message);
				AdeNetSingleSignOn.Log.Error(strMessage, ex, request);
				return ValidateResult.Failure("An error occured while validating the signature-certificate.");
			}

			return ValidateResult.Success;
		}
		#endregion
	}
}