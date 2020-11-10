const constants = require("./Constants")
const Sign = require("./Sign")

const NS = {
    "xmlns:cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
    "xmlns:ext": "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
    "xmlns:cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
    "xmlns:sts": "http://www.dian.gov.co/contratos/facturaelectronica/v1/Structures",
    "xmlns": "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
    "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
    "xmlns:xades141": "http://uri.etsi.org/01903/v1.4.1#",
    "xmlns:xades": "http://uri.etsi.org/01903/v1.3.2#",
    "xmlns:ds": constants.XMLDSIG
}

//XMLDSIG
const XMLDSIG = "http://www.w3.org/2000/09/xmldsig#";

//POLITICA_FIRMA_V2
const POLITICA_FIRMA_V2 = "https://facturaelectronica.dian.gov.co/politicadefirma/v2/politicadefirmav2.pdf";

//POLITICA_FIRMA_V2_VALUE
const POLITICA_FIRMA_V2_VALUE = "dMoMvtcG5aIzgYo0tIsSQeVJBDnUnfSOfBpxXrmor0Y=";

//C14N
const C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

//ENVELOPED_SIGNATURE
const ENVELOPED_SIGNATURE = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

//SIGNED_PROPERTIES
const SIGNED_PROPERTIES = "http://uri.etsi.org/01903#SignedProperties";

const ids = {
    "SignedPropertiesID": "SIGNED-PROPS",
    "SignatureValueID": "SIG-VALUE",
    "SignatureID": "SOENAC",
    "KeyInfoID": "KEY-INFO",
    "ReferenceID": "REF",
}

const groupOfTotals = 'LegalMonetaryTotal';

class SignInvoice extends Sign {
    constructor(pathCertificate, password = '', xmlString, algorithm = constants.ALGO_SHA256) {
        super(pathCertificate, password, xmlString)
        this.algorithm = algorithm
    }
}

module.exports = SignInvoice