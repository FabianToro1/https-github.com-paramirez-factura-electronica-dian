const FacturaElectronicaDian = require("./FacturaElectronicaDian")
const cert = require("./cert")
const facturaElectronicaDian = new FacturaElectronicaDian(cert, "lacontraseña")
facturaElectronicaDian.GetStatus("31c195089a1c2f133314335f907fe56d3908cb0")