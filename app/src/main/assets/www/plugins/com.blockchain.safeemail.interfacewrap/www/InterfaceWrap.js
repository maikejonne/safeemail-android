cordova.define("com.blockchain.safeemail.interfacewrap.InterfaceWrap", function(require, exports, module) {
//////////////////////////////////////////
// Cache.js
// Copyright (C) 2014 Modern Alchemits OG <office@modalog.at>
//
//////////////////////////////////////////
var exec = require('cordova/exec');

var InterfaceWrap =
{
    isIgnoringBatteryOptimizations : function( success, error )
    {
        exec(success, error, "InterfaceWrap", "isIgnoringBatteryOptimizations", [])
    },

    internetWhiteListRequest : function( success, error )
    {
        exec(success, error, "InterfaceWrap", "internetWhiteListRequest", [])
    },

    tryLogin : function(success, fail){
        exec(success, fail, "InterfaceWrap", "tryLogin", []);
    },

    removePrivateKey : function(success, fail){
        exec(success, fail, "InterfaceWrap", "removePrivateKey", []);
    },

    decryptPrivateKey : function(pw, success, fail){
        exec(success, fail, "InterfaceWrap", "decryptPrivateKey", [pw]);
    },

    encryptPrivateKey : function(pw, success, fail){
        exec(success, fail, "InterfaceWrap", "encryptPrivateKey", [pw]);
    },

    encryptDataByFile : function(password, path, success, fail){
        exec(success, fail, "InterfaceWrap", "encryptDataByFile", [password, path]);
    },

    decryptDataByFile : function(password, path, rootDir, destFileName, success, fail){
        exec(success, fail, "InterfaceWrap", "decryptDataByFile", [password, path, rootDir, destFileName]);
    },

    loginFromFile : function(path, success, fail){
        exec(success, fail, "InterfaceWrap", "loginFromFile", [path]);
    },

    exportPrivateKey : function(path, success, fail){
        exec(success, fail, "InterfaceWrap", "exportPrivateKey", [path]);
    },

    revertPrivateKeyLevel : function(success, fail){
        exec(success, fail, "InterfaceWrap", "revertPrivateKeyLevel", []);
    },

    ECIESEncrypt : function(pubkey, data, success, fail){
        exec(success, fail, "InterfaceWrap", "ECIESEncrypt", [pubkey, data]);
    },

    ECIESEncryptSelf : function(data, keyPairType, success, fail){
        exec(success, fail, "InterfaceWrap", "ECIESEncryptSelf", [data, keyPairType]);
    },

    ECIESDecrypt : function(data, userIndex, keyPairType, success, fail){
        exec(success, fail, "InterfaceWrap", "ECIESDecrypt", [data, userIndex, keyPairType]);
    },

    generatePrivateKey : function(success, fail){
       exec(success, fail, "InterfaceWrap", "generatePrivateKey", []);
    },

    computePubkey : function(keyPairType, success, fail){
       exec(success, fail, "InterfaceWrap", "computePubkey", [keyPairType]);
    },

    sign : function(data, userIndex, keyPairType, success, fail){
      exec(success, fail, "InterfaceWrap", "sign", [data, userIndex, keyPairType]);
    },

    sign_recoverable : function(data, userIndex, keyPairType, success, fail){
      exec(success, fail, "InterfaceWrap", "sign_recoverable", [data, userIndex, keyPairType]);
    },

    getCurrentUserIndex:function(success, fail){
        exec(success, fail, "InterfaceWrap", "getCurrentUserIndex", []);
    },

    setCurrentUserIndex:function(index, success, fail){
        exec(success, fail, "InterfaceWrap", "setCurrentUserIndex", [index]);
    },

    addNewUser:function(data, success, fail){
        exec(success, fail, "InterfaceWrap", "addNewUser", [data]);
    },

    generateNewUser:function(success, fail){
        exec(success, fail, "InterfaceWrap", "generateNewUser", []);
    },

    generateSubKeyPair:function(success, fail){
        exec(success, fail, "InterfaceWrap", "generateSubKeyPair", []);
    },

    removeUser:function(index, success, fail){
        exec(success, fail, "InterfaceWrap", "removeUser", [index]);
    },

    modifyUserLabel:function(index, label, success, fail){
        exec(success, fail, "InterfaceWrap", "modifyUserLabel", [index, label]);
    },

    modifyUserHost:function(index, host, success, fail){
        exec(success, fail, "InterfaceWrap", "modifyUserHost", [index, host]);
    },

    copyToClipBoard:function(content, success, fail){
         exec(success, fail, "InterfaceWrap", "copyToClipBoard", [content]);
    },

    compressVideo:function(path, w, h, destPath, destFileName, success, fail){
        exec(success, fail, "InterfaceWrap", "compressVideo", [path, w, h, destPath, destFileName]);
    },

    compressAudio:function(path, destPath, destFileName, success, fail){
        exec(success, fail, "InterfaceWrap", "compressAudio", [path, destPath, destFileName]);
    },

    hasRecordAudioPermission:function(success, fail){
        exec(success, fail, "InterfaceWrap", "hasRecordAudioPermission", []);
    },

    getAudioDuration:function(path, success, fail){
        exec(success, fail, "InterfaceWrap", "getAudioDuration", [path]);
    },

    downloadFile:function(url, success, fail){
        exec(success, fail, "InterfaceWrap", "downloadFile", [url]);
    },

    combineFile:function(path, header, destFileName, flag, success, fail){
        exec(success, fail, "InterfaceWrap", "combineFile", [path, header, destFileName, flag]);
    },

    getCurrentLocale:function(success, fail){
        exec(success, fail, "InterfaceWrap", "getCurrentLocale", []);
    },

    getFileLength:function(path, success, fail){
        exec(success, fail, "InterfaceWrap", "getFileLength", [path]);
    },

    startInstallApk:function(path, success, fail){
        exec(success, fail, "InterfaceWrap", "startInstallApk", [path]);
    },

    hasExternalStoragePermission:function(success, fail){
        exec(success, fail, "InterfaceWrap", "hasExternalStoragePermission", []);
    },

    requestExternalStoragePermission:function(success, fail){
        exec(success, fail, "InterfaceWrap", "requestExternalStoragePermission", []);
    },

    requestAudioPermission:function(success, fail){
        exec(success, fail, "InterfaceWrap", "requestAudioPermission", []);
    },

    getVersionCode:function(success, fail){
        exec(success, fail, "InterfaceWrap", "getVersionCode", []);
    },

    createDirectorys:function(path, success, fail){
        exec(success, fail, "InterfaceWrap", "createDirectorys", [path]);
    },
}

module.exports = InterfaceWrap;

});
