const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const app = express();
const AES = require("aes-js");

app.use(cors());
app.use(
	bodyParser.urlencoded({
		limit: "50mb",
		extended: true,
		parameterLimit: 1000000,
	})
);
app.use(
	bodyParser.json({
		limit: "50mb",
		extended: true,
		parameterLimit: 1000000,
	})
);

const encrypt = (data, token, cipherIV) => {
	const key = AES.utils.utf8.toBytes(token);
	const iv = AES.utils.utf8.toBytes(cipherIV);
	const aesCbc = new AES.ModeOfOperation.cbc(key, iv);
	const dataBytes = AES.utils.utf8.toBytes(data);
	const paddedData = AES.padding.pkcs7.pad(dataBytes);
	const encryptedBytes = aesCbc.encrypt(paddedData);
	return encryptedBytes;
};
const decrypt = (data, token, cipherIV) => {
	const key = AES.utils.utf8.toBytes(token);
	const iv = AES.utils.utf8.toBytes(cipherIV);
	const aesCbc = new AES.ModeOfOperation.cbc(key, iv);
	const decryptedData = aesCbc.decrypt(data);
	const unpadData = AES.padding.pkcs7.strip(decryptedData);

	return AES.utils.utf8.fromBytes(unpadData);
	// return decryptedData;
};
//Routes
app.post("/encrypt", (req, res) => {
	let { data } = req.body;
	console.log(req.body);
	//  data = JSON.stringify({ name: "Rohan", age: 12 });
	// var message = "Hello World";
	var token = process.env.key;
	var cipherIV = process.env.iv;
	var result = encrypt(JSON.stringify(data), token, cipherIV);
	console.log(result);
	res.json({
		message: "success",
		encrypted: Buffer.from(result).toString("base64"),
	});
});

app.post("/decrypt", (req, res) => {
	let { encrypted } = req.body;
	//coverting from base64 to uint8
	let encrptedBytes = new Uint8Array(Buffer.from(encrypted, "base64"));
	console.log(encrptedBytes);
	var token = process.env.key;
	var cipherIV = process.env.iv;
	var result = decrypt(encrptedBytes, token, cipherIV);
	res.json({
		message: "success",
		decrypted: JSON.parse(result),
	});
});

(startServer = () => {
	try {
		app.listen(process.env.PORT || 5000);
		console.log("APP STARTED");
	} catch (err) {
		console.error("Error in running server.", err);
	}
})();
