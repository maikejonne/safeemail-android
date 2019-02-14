cordova.define("cordova-plugin-secp256k1.secp256k1", function(require, exports, module) {
/*
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
*/

/**
 * This class contains information about the current battery status.
 * @constructor
 */
var cordova = require('cordova');
var exec = require('cordova/exec');


var secp256k1 = {};


secp256k1.verify = function(callback, data, signature, pub){
   exec(callback, function(err) {
            console.log('verify error.');
       }, "Secp256k1", "verify", [data, signature, pub]);
};

secp256k1.verify_recoverable = function( data, rsignature, pub, success, fail){
   exec(success, fail, "Secp256k1", "verify_recoverable", [data, rsignature, pub]);
};

secp256k1.secKeyVerify= function(){

};

secp256k1.cloneContext= function(){

};

secp256k1.privKeyTweakMul= function(){

};

secp256k1.privKeyTweakAdd= function(){

};

secp256k1.pubKeyTweakAdd= function(){

};

secp256k1.pubKeyTweakMul= function(){

};

secp256k1.createECDHSecret= function(){

};

secp256k1.encryptData = function(pubkey, data, success, fail){
    exec(success, fail, "Secp256k1", "encryptData", [pubkey, data]);
};

secp256k1.decryptData = function(data, success, fail){
    exec(success, fail, "Secp256k1", "decryptData", [data]);
};

secp256k1.encryptDataSelf = function(data, success, fail){
    exec(success, fail, "Secp256k1", "encryptDataSelf", [data]);
};

secp256k1.generateAddressForKey = function(pubkey, success, fail){
    exec(success, fail, "Secp256k1", "generateAddressForKey", [pubkey]);
};

secp256k1.recoverPubkeyFromRsig = function(data, sign,success, fail){
    exec(success, fail, "Secp256k1", "recoverPubkeyFromRsig", [data, sign]);
};

secp256k1.randomize= function(callback, seed){
   exec(callback, function(err) {
           console.log('randomize error.');
       }, "Secp256k1", "randomize", [seed]);
};

secp256k1.simpleEncrypt = function(password, data, success, fail){
     exec(success, fail, "Secp256k1", "simpleEncrypt", [password, data]);
};

secp256k1.simpleDecrypt = function(password, data, success, fail){
     exec(success, fail, "Secp256k1", "simpleDecrypt", [password, data]);
};

secp256k1.decryptDataBySimpleFile = function(password, path, rootDir, destFileName, success, fail){
    exec(success, fail, "Secp256k1", "decryptDataBySimpleFile", [password, path, rootDir, destFileName]);
};

module.exports = secp256k1;
});
