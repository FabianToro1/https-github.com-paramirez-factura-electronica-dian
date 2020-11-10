const Sign = require("./Sign");
const {
    DOMParser,
    XMLSerializer
} = require("xmldom");
const c14n = require("xml-c14n")
const fs = require("fs")
const crypto = require("crypto")
const Constants = require("./Constants");
const axios = require("axios").default

const ids = {
    // 'wsuBinarySecurityTokenID': 'SOENAC',
    'wsuBinarySecurityTokenID': 'X509',
    'securityTokenReferenceID': 'STR',
    'signatureID': 'SIG',
    'timestampID': 'TS',
    'keyInfoID': 'KI',
    'wsuIDTo': 'ID',
}

async function SendRequest(url, data) {
    return axios.post(url, data, {
        headers: {
            'content-type': 'application/soap+xml;charset=utf-8'
        }
    })
}

class SOAP extends Sign {
    /**
     * @param {string} p12Base64 
     * @param {string} password 
     * @param {string} to Constants.DIAN
     */
    constructor(p12Base64, password, prod) {
        super(p12Base64, password)
        this.to = prod ? Constants.DIAN["wsdl"] : Constants.DIAN["wsdl-hab"]
        this.to = this.to.replace('?wsdl', '')
    }

    /**
     * @override
     */
    async loadXML(xmlFileName, values) {
        let xmlString = fs.readFileSync(xmlFileName + ".xml", "utf-8")
        const soapValues = {
            ...this.soapValues,
            ...values,
            To: this.to
        }
        Object.keys(soapValues).forEach(key =>
            xmlString = xmlString.replace(new RegExp("__" + key, 'g'), soapValues[key])
        )

        const domDocument = new DOMParser().parseFromString(xmlString)

        // console.log("entro ", new XMLSerializer().serializeToString(domDocument))

        const securityElements = domDocument.getElementsByTagNameNS(Constants.WSS_WSSECURITY, "Security")
        if (securityElements.length < 1) throw new Error("Not wsse:Security ELEMENT in template")

        const security = securityElements.item(0)

        const signature = domDocument.createElement("ds:Signature")
        signature.setAttribute("Id", ids.signatureID + `-${soapValues.Id}`)
        signature.setAttribute('xmlns:ds', Constants.XMLDSIG);
        security.appendChild(signature)

        const signedInfo = domDocument.createElement('ds:SignedInfo');
        signature.appendChild(signedInfo);

        const canonicalizationMethod = domDocument.createElement('ds:CanonicalizationMethod');
        canonicalizationMethod.setAttribute('Algorithm', Constants.EXC_C14N);
        signedInfo.appendChild(canonicalizationMethod);

        const inclusiveNamespaces1 = domDocument.createElement('ec:InclusiveNamespaces');
        inclusiveNamespaces1.setAttribute('PrefixList', 'wsa soap wcf');
        inclusiveNamespaces1.setAttribute('xmlns:ec', Constants.EXC_C14N);
        canonicalizationMethod.appendChild(inclusiveNamespaces1);

        const signatureMethod = domDocument.createElement('ds:SignatureMethod');
        signatureMethod.setAttribute('Algorithm', Constants.RSA_SHA256);
        signedInfo.appendChild(signatureMethod);

        const reference1 = domDocument.createElement('ds:Reference');
        reference1.setAttribute('URI', ids.wsuIDTo + `-${soapValues.Id}`);
        signedInfo.appendChild(reference1);

        const transforms = domDocument.createElement('ds:Transforms');
        reference1.appendChild(transforms);

        const transform = domDocument.createElement('ds:Transform');
        transform.setAttribute('Algorithm', Constants.EXC_C14N);
        transforms.appendChild(transform);

        const inclusiveNamespaces2 = domDocument.createElement('ec:InclusiveNamespaces');
        inclusiveNamespaces2.setAttribute('PrefixList', 'soap wcf');
        inclusiveNamespaces2.setAttribute('xmlns:ec', Constants.EXC_C14N);
        transform.appendChild(inclusiveNamespaces2);

        const digestMethod = domDocument.createElement('ds:DigestMethod');
        digestMethod.setAttribute('Algorithm', Constants.SHA256);
        reference1.appendChild(digestMethod);

        // DigestValue
        const canonicaliser = c14n().createCanonicaliser(Constants.EXC_C14N);
        const canonicalised = await new Promise((resolve, reject) =>
            canonicaliser.canonicalise(domDocument.documentElement, (err, data) => err ? reject(err) : resolve(data))
        )
        const digestValueBase64 = crypto.createHash('sha256').update(canonicalised).digest('base64');
        const digestValue = domDocument.createElement('ds:DigestValue');
        digestValue.textContent = digestValueBase64
        reference1.appendChild(digestValue);

        //SignatureValue
        const signBuffer = crypto.sign("sha256", Buffer.from(canonicalised), {
            key: soapValues.___key,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING
        })

        const isVerify = crypto.verify("sha256", Buffer.from(canonicalised), {
            key: soapValues.___cert,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING
        }, signBuffer)
        if (!isVerify) throw new Error("El contenido del archivo no se pudo verificar con llave publica")

        const signatureValue = domDocument.createElement('ds:SignatureValue');
        signatureValue.textContent = signBuffer.toString("base64")
        signature.appendChild(signatureValue);

        const keyInfo = domDocument.createElement('ds:KeyInfo');
        keyInfo.setAttribute('Id', ids.keyInfoID + `-${soapValues.Id}`);
        signature.appendChild(keyInfo);

        const securityTokenReference = domDocument.createElement('wsse:SecurityTokenReference');
        securityTokenReference.setAttribute('wsu:Id', ids.securityTokenReferenceID + `-${soapValues.Id}`);
        keyInfo.appendChild(securityTokenReference);

        const reference2 = domDocument.createElement('wsse:Reference');
        reference2.setAttribute('URI', ids.wsuBinarySecurityTokenID + `-${soapValues.Id}`);
        reference2.setAttribute('ValueType', Constants.X509V3);
        securityTokenReference.appendChild(reference2);

        return SendRequest(this.to, new XMLSerializer().serializeToString(domDocument))
    }

}

module.exports = SOAP