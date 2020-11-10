//ADDRESSING
const ADDRESSING = "http://www.w3.org/2005/08/addressing";

//SOAP_ENVELOPE
const SOAP_ENVELOPE = "http://www.w3.org/2003/05/soap-envelope";

//DIAN_COLOMBIA
const DIAN_COLOMBIA = "http://wcf.dian.colombia";

//XMLDSIG
const XMLDSIG = "http://www.w3.org/2000/09/xmldsig#";

//WSS_WSSECURITY
const WSS_WSSECURITY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

//WSS_WSSECURITY_UTILITY
const WSS_WSSECURITY_UTILITY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

//EXC_C14N
const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

//RSA_SHA256
const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

//SHA256
const SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

//X509V3
const X509V3 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";

//BASE64BINARY
const BASE64BINARY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";

//ALGO_SHA1
const ALGO_SHA1 = {
    "rsa": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1",
    "algorithm": "http://www.w3.org/2001/04/xmlenc#sha1",
    "sign": "OPENSSL_ALGO_SHA1",
    "hash": "sha1",
}
//ALGO_SHA256
const ALGO_SHA256 = {
    "rsa": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "algorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
    "sign": "OPENSSL_ALGO_SHA256",
    "hash": "sha256",
}
//ALGO_SHA512
const ALGO_SHA512 = {
    "rsa": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
    "algorithm": "http://www.w3.org/2001/04/xmlenc#sha512",
    "sign": "OPENSSL_ALGO_SHA512",
    "hash": "sha512",
}


const DIAN = {
    'wsdl-hab': 'https://vpfe-hab.dian.gov.co/WcfDianCustomerServices.svc?wsdl',
    'wsdl': 'https://vpfe.dian.gov.co/WcfDianCustomerServices.svc?wsdl',
    'catalogo-hab': 'https://catalogo-vpfe-hab.dian.gov.co/Document/FindDocument?documentKey={}&partitionKey={}&emissionDate={}',
    'catalogo': 'https://catalogo-vpfe.dian.gov.co/Document/FindDocument?documentKey={}&partitionKey={}&emissionDate={}'
}

module.exports = {
    ADDRESSING,
    SOAP_ENVELOPE,
    DIAN_COLOMBIA,
    XMLDSIG,
    WSS_WSSECURITY,
    WSS_WSSECURITY_UTILITY,
    EXC_C14N,
    RSA_SHA256,
    SHA256,
    X509V3,
    BASE64BINARY,
    ALGO_SHA1,
    ALGO_SHA256,
    ALGO_SHA512,
    DIAN
}