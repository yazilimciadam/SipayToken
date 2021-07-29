var crypto = require("crypto")
module.exports.CreateHashKey = (total,taksit,currency,order_id,callback)=>{
    var encrypt = function (plain_text, encryptionMethod, secret, iv) {
        var encryptor = crypto.createCipheriv(encryptionMethod, secret, iv);
        return encryptor.update(plain_text, 'utf8', 'base64') + encryptor.final('base64');
    };
       
        
        var data = parseFloat(total/100).toFixed(2)+"|"+parseInt(taksit)+"|"+currency+"|"+process.env.MERCHANT_KEY_SIPAY+"|"+order_id;
       
        var iv1 = crypto.createHash("sha1").update(Math.floor(100000000 + Math.random() * 900000000).toString()).digest("hex")
        var iv = iv1.substr(0,16)
        var pass = crypto.createHash("sha1").update(process.env.APP_SECRET_SIPAY).digest("hex")
        var sal2 = crypto.createHash("sha1").update(Math.floor(100000000 + Math.random() * 900000000).toString()).digest("hex")
        var salt = sal2.substr(0,4)
        var saltPass = crypto.createHash("sha256").update(pass+salt).digest("hex").substr(0, 32);
    
        var enc = encrypt(data,'AES-256-CBC',saltPass.toString(),iv);
        var msgBundle = iv+":"+salt+":"+enc
       
        var bb = msgBundle.split('/').join("__");
    
       callback(null,bb)
  
   

}

module.exports.CreateHashKeyCashOut = (toplamsayi,iban,toplampara,currency,gsm,callback)=>{
    var encrypt = function (plain_text, encryptionMethod, secret, iv) {
        var encryptor = crypto.createCipheriv(encryptionMethod, secret, iv);
        return encryptor.update(plain_text, 'utf8', 'base64') + encryptor.final('base64');
    };
    
    
        var data = parseInt(toplamsayi)+"|"+iban+"|"+ parseInt(toplampara) +"|"+currency+"|"+gsm;
       
        var iv1 = crypto.createHash("sha1").update(Math.floor(100000000 + Math.random() * 900000000).toString()).digest("hex")
        var iv = iv1.substr(0,16)
        var pass = crypto.createHash("sha1").update(process.env.APP_SECRET_SIPAY).digest("hex")
        var sal2 = crypto.createHash("sha1").update(Math.floor(100000000 + Math.random() * 900000000).toString()).digest("hex")
        var salt = sal2.substr(0,4)
        var saltPass = crypto.createHash("sha256").update(pass+salt).digest("hex").substr(0, 32);
    
        var enc = encrypt(data,'AES-256-CBC',saltPass.toString(),iv);
        var msgBundle = iv+":"+salt+":"+enc
       
        var bb = msgBundle.split('/').join("__");
    
       callback(null,bb)
  
   

}


module.exports.CreateHashKeyStatus = (order_id,callback)=>{
    var encrypt = function (plain_text, encryptionMethod, secret, iv) {
        var encryptor = crypto.createCipheriv(encryptionMethod, secret, iv);
        return encryptor.update(plain_text, 'utf8', 'base64') + encryptor.final('base64');
    };
       
        
        var data = order_id+"|"+process.env.MERCHANT_KEY_SIPAY+"|"
       
        var iv1 = crypto.createHash("sha1").update(Math.floor(100000000 + Math.random() * 900000000).toString()).digest("hex")
        var iv = iv1.substr(0,16)
        var pass = crypto.createHash("sha1").update(process.env.APP_SECRET_SIPAY).digest("hex")
        var sal2 = crypto.createHash("sha1").update(Math.floor(100000000 + Math.random() * 900000000).toString()).digest("hex")
        var salt = sal2.substr(0,4)
        var saltPass = crypto.createHash("sha256").update(pass+salt).digest("hex").substr(0, 32);
    
        var enc = encrypt(data,'AES-256-CBC',saltPass.toString(),iv);
        var msgBundle = iv+":"+salt+":"+enc
       
        var bb = msgBundle.split('/').join("__");
    
       callback(null,bb)
  
   

}

module.exports.DecryptHashKeyStatus = (hash,callback)=>{
    var decrytp = function (encryptedMessage, secret, iv) {
        var decryptor = crypto.createDecipheriv('AES-256-CBC', secret,iv);
        return decryptor.update(encryptedMessage, 'base64', 'utf8') + decryptor.final('utf8');
   
    };
       
        
        var hash_key = hash.split("__").join("/") 
        var pass = crypto.createHash("sha1").update(process.env.APP_SECRET_SIPAY).digest("hex")
        var comp = hash_key.split(":")
        var saltPass = crypto.createHash("sha256").update(pass+comp[1]).digest("hex").substr(0, 32);
       
        var bba = decrytp(comp[2],saltPass.toString(),comp[0]).split("|")
        
       callback(null,{status:bba[0],total:bba[1], invoice_id:bba[2], order_id:bba[3], currency:bba[4]})
  
   

}