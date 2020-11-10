const pem = require("pem")

function uuidv4() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = Math.random() * 16 | 0,
            v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

function addMinutes(date, minutes) {
    return new Date(date.getTime() + minutes * 60000);
}

/**
 * @typedef {object} SoapValues
 * @property {string} Created
 * @property {string} Expires
 * @property {string} BinarySecurityToken
 * @property {string} Id
 * @property {string} ___key
 */

/**
 * @param {string} p12Base64 
 * @param {string} p12Password 
 * @returns {Promise.<SoapValues>}
 */
function SoapValues(p12Base64, p12Password) {
    return new Promise((resolve, reject) => {
        const p12Buffer = Buffer.from(p12Base64, "base64")
        pem.readPkcs12(p12Buffer, {
            p12Password
        }, (err, p12Content) => {
            const date = new Date()
            const Created = date.toISOString()
            const Expires = addMinutes(date, 1020).toISOString()
            if (err) return reject(err)
            const BinarySecurityToken = p12Content.cert.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace(/\n|\r/g, "")
            resolve({
                Created,
                Expires,
                BinarySecurityToken,
                Id: uuidv4(),
                ___key: p12Content.key,
                ___cert: p12Content.cert
            })
        })

    })
}

class Sign {
    constructor(p12Base64, password = '') {
        if (!p12Base64 || !password) throw new Error("Cert and password is required")
        this.p12Base64 = p12Base64
        this.password = password
        /**
         * @type {SoapValues}
         */
        this.soapValues = null
    }

    /**
     * Abstarct function
     * @returns {Promise.<{}>}
     */
    async loadXML() {
        throw new Error("Unimplement method sign")
    }

    async sign(string, values) {
        if (!this.soapValues) {
            const soapValues = await SoapValues(this.p12Base64, this.password)
            this.soapValues = soapValues
        }
        return await this.loadXML(string, values)
    }

}

module.exports = Sign