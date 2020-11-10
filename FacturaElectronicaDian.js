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
        }).catch(error => {
            if (error.response) {
                // Request made and server responded
                console.log(error.response.data);
                console.log(error.response.status);
                console.log(error.response.headers);
            } else if (error.request) {
                // The request was made but no response was received
                console.log(error.request);
            } else {
                // Something happened in setting up the request that triggered an Error
                console.log('Error', error.message);
            }
        })
    }
}

module.exports = FacturaElectronicaDian