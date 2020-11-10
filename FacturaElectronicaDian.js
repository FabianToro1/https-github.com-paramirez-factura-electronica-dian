const Constants = require("./Constants")
const SOAP = require("./SOAP")

class FacturaElectronicaDian {
    /**
     * @param {string} p12Base64 
     * @param {string} password 
     */
    constructor(p12Base64, password) {
        this.soap = new SOAP(p12Base64, password)
    }

    /**
     * @param {String} trackId 
     */
    GetStatus(trackId) {
        this.soap.sign("GetStatus", {
            trackId
        }).then(response => {
            console.log(response)
        }).catch(err => {
            console.log(err)
        })
    }
}

module.exports = FacturaElectronicaDian