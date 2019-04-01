
var nativeInterfaceHelper = {

    ///////////////file///////////////////


    findFile:function(path, success, fail){
        window.resolveLocalFileSystemURL(path, function (fileEntry) {
            fileEntry.file(function (file) {
                success();
            }, fail.bind(null, path));
        }, fail.bind(null, path));
    },

    createFile:function(rootDir, fileName, success, fail){
        window.resolveLocalFileSystemURL(rootDir, function (dirEntry) {
            // Creates a new file or returns the file if it already exists.
            dirEntry.getFile(fileName, {create: true, exclusive: false}, function(fileEntry) {
                success();
            }, fail.bind(null, fileName));
        }, fail.bind(null, rootDir));
    },

    writeFile:function(rootDir, fileName, data, success, fail){
        window.resolveLocalFileSystemURL(rootDir, function (dirEntry) {
            dirEntry.getFile(fileName, { create: true, exclusive: false }, function (fileEntry) {
               // Create a FileWriter object for our FileEntry (log.txt).
                fileEntry.createWriter(function (fileWriter) {

                    fileWriter.onwriteend = function() {
                        success();
                    };

                    fileWriter.onerror = function (e) {
                        fail(e.toString());
                    };

                    var dataObj = new Blob([data], { type: 'text/plain' });
                    fileWriter.write(dataObj);
                });
            }, fail.bind(null, fileName));
        }, fail.bind(null, rootDir));
    },

    writeFileAsType:function(rootDir, fileName, data, mimeType, success, fail){
        nativeInterfaceHelper.createDirectorys(rootDir, function(){
            window.resolveLocalFileSystemURL(rootDir, function (dirEntry) {
                dirEntry.getFile(fileName, { create: true, exclusive: false }, function (fileEntry) {
                   // Create a FileWriter object for our FileEntry (log.txt).
                    fileEntry.createWriter(function (fileWriter) {
                        fileWriter.onwriteend = function() {
                            success();
                        };

                        fileWriter.onerror = fail;

                        var dataObj = new Blob([data], { type: mimeType });
                        fileWriter.write(dataObj);
                    });
                }, fail.bind(null, fileName));
            }, fail.bind(null, rootDir));
        }, fail.bind(null, rootDir));
    },

    readFile:function (path, success, fail) {
        window.resolveLocalFileSystemURL(path, function (fileEntry) {
            fileEntry.file(function (file) {
                var reader = new FileReader();
                reader.onload = function() {
                    success(this.result);
                };
                reader.onerror = function () {
                    fail("read file error.");
                };
                reader.readAsText(file);

            }, fail.bind(null, path));
        }, fail.bind(null, path));
    },

    readFileByType:function(path, fileType, success, fail){
        window.resolveLocalFileSystemURL(path, function (fileEntry) {
            fileEntry.file(function (file) {
                var reader = new FileReader();
                reader.onload = function() {
                    success(this.result);
                };
                reader.onerror = function () {
                    fail("read file error.");
                };
                if(fileType == "text"){
                    reader.readAsText(file);
                } else if(fileType == "dataUrl"){
                    reader.readAsDataURL(file);
                } else {
                    reader.readAsArrayBuffer(file);
                }

            }, fail.bind(null, path));
        }, fail.bind(null, path));
    },

    createDirectory:function(rootDir, subDir, success, fail){
        window.resolveLocalFileSystemURL(rootDir, function (dirEntry) {
            dirEntry.getDirectory(subDir, { create: true, exclusive: false }, function (subDirEntry) {
                success();
            }, fail.bind(null, subDir));
        }, fail.bind(null, rootDir));
    },

    createDirectorys:function(path, success, fail){
        InterfaceWrap.createDirectorys(path, success, fail);
    },

    removeFile:function(path, success, fail){
        window.resolveLocalFileSystemURL(path, function (fileEntry) {
            fileEntry.remove(success, fail.bind(null, path));
        }, fail.bind(null, path));
    },

    removeDirectory:function(rootDir, success, fail){
        window.resolveLocalFileSystemURL(rootDir, function (dirEntry) {
            dirEntry.removeRecursively(success, fail.bind(null, rootDir));
        }, fail.bind(null, rootDir));
    },


    ////////////////////////////////////


    /////////////////key pair/////////////////

    generatePrivateKey:function(success, fail){
        InterfaceWrap.generatePrivateKey(success, fail);
    },

    generatePublicKey:function(privkey, success, fail){
        InterfaceWrap.computePubkey(privkey, success, fail);
    },

    decryptPrivateKey:function(password, success, fail){
        InterfaceWrap.decryptPrivateKey(password, success, fail);
    },

    encryptPrivateKey:function(password, success, fail){
        InterfaceWrap.encryptPrivateKey(password, success, fail);
    },

    encryptData:function(pubkey, data, success, fail){
        InterfaceWrap.ECIESEncrypt(pubkey, data, success, fail);
    },

    encryptDataSelf:function(data, keyPairType, success, fail){
        InterfaceWrap.ECIESEncryptSelf(data, keyPairType, success, fail);
    },

    decryptData:function(data, userIndex, keyPairType, success, fail){
        InterfaceWrap.ECIESDecrypt(data, userIndex, keyPairType, success, fail);
    },

    sign:function(data, userIndex, keyPairType, success, fail){
        InterfaceWrap.sign_recoverable(data, userIndex, keyPairType, success, fail);
    },

    verify:function(data, rsignature, pub, success, fail){
        cordova.plugins.secp256k1.verify_recoverable(data, rsignature, pub, success, fail);
    },

    recoverPublicKeyFromSig:function(data, rsignature, success, fail){
        cordova.plugins.secp256k1.recoverPubkeyFromRsig(data, rsignature, success, fail);
    },

    //////////////////////////////////////////

    encryptDataByBFNoSign:function(password, data, success, fail){
        cordova.plugins.secp256k1.simpleEncrypt(password, data, success, fail);
    },

    encryptDataByBF:function(password, data, success, fail){
        cordova.plugins.secp256k1.simpleEncrypt(password, data, function(encryptedData){
            nativeInterfaceHelper.sign(encryptedData, function(signature){
                success({"signature": signature, "data":encryptedData });
            }, fail);
        }, fail);
    },

    decryptDataByBF:function(password, data, success, fail){
        cordova.plugins.secp256k1.simpleDecrypt(password, data, success, fail);
    },

    //////////////////////////////////////////

    imagePicker:function(success, fail){
        window.imagePicker.getPictures(
            success, fail, {
                maximumImagesCount: 1,
            }
        );
    },

    videoPicker:function(success, fail){
        var args = {
            'selectMode': 102, //101=picker image and video , 100=image , 102=video
            'maxSelectCount': 1, //default 40 (Optional)
            'maxSelectSize': 188743680, //188743680=180M (Optional)
        };
        MediaPicker.getMedias(args, function(medias) {
            //medias [{mediaType: "image", path:'/storage/emulated/0/DCIM/Camera/2017.jpg', uri:"android retrun uri,ios retrun URL" size: 21993}]
            if(medias.length <=0){
                if(fail) fail("not select anything!");
                return;
            }
            nativeInterfaceHelper.getThumbnail(medias[0], success, fail);
        }, fail);
    },

    getThumbnail:function(media, success, fail) {
        //medias[i].thumbnailQuality=50; (Optional)
        media.thumbnailQuality = 10;
        //loadingUI(); //show loading ui
        MediaPicker.extractThumbnail(media, function(data) {
            media.thumbnail = 'data:image/jpeg;base64,' + data.thumbnailBase64;
            media.path = "file://" + media.path;
            var _img = new Image();
            _img.onload = function(){
                media.thumbnailWidth = _img.width;
                media.thumbnailHeight = _img.height;
                if(success) success(media);
            };
            _img.src = media.thumbnail;
        }, fail);
    },

    getThumbnailByPath:function(path, success, fail) {
        var media = {};
        media.thumbnailQuality = 50;
        media.path = path.replace("file://", "");
        media.mediaType = "video";
        MediaPicker.extractThumbnail(media, function(data) {
            var result = {};
            result.thumbnail = 'data:image/jpeg;base64,' + data.thumbnailBase64;
            var _img = new Image();
            _img.onload = function(){
                result.thumbnailWidth = _img.width;
                result.thumbnailHeight = _img.height;
                if(success) success(result);
            };
            _img.src = result.thumbnail;
        }, fail);
    },

    copyToClipBoard:function(content, success, fail){
        InterfaceWrap.copyToClipBoard(content, success, fail);
    },

    encryptNWriteFile:function(pubkey, rawData, rootDir, fileName, success, fail){
        nativeInterfaceHelper.encryptData(pubkey, rawData,function(data){
            nativeInterfaceHelper.writeFile(rootDir, fileName, data, function(){
                if(success) success(data);
            }, fail);
        }, fail);
    },

    decryptNReadFile:function(rootDir, fileName, success, readFail, decryptFail){
         nativeInterfaceHelper.readFile(rootDir + fileName, function(data){
            nativeInterfaceHelper.decryptData(data, function(decryptData){
                success(decryptData);
            }, decryptFail);
         }, readFail);
    },

    tryLogin:function(success, fail){
        InterfaceWrap.tryLogin(success, function(err){
            if(err == 1 || err == "1"){
                fail(1);
            } else {
                var path =  cordova.file.applicationStorageDirectory + "privatekey.keystore";
                nativeInterfaceHelper.removeFile(path, function(){}, function(){});
                fail(0);
            }
        });
    },

    loginFromFile:function(path, success, fail){
        InterfaceWrap.loginFromFile(path, success, fail);
    },

    exportPrivateKey:function(path, success, fail){
        InterfaceWrap.exportPrivateKey(path, success, fail);
    },

    revertPrivateKeyLevel:function(success, fail){
        InterfaceWrap.revertPrivateKeyLevel(success, fail);
    },

    removePrivateKey:function(success, fail){
        var path =  cordova.file.applicationStorageDirectory + "privatekey.keystore";
        nativeInterfaceHelper.removeFile(path, success, fail);
        InterfaceWrap.removePrivateKey(function(){}, function(err){});
    },

    encryptDataByFile:function(password, path, success, fail){
        InterfaceWrap.encryptDataByFile(password, path, function(result){
            if(!result || result.length < 4){
                fail("json stringify list data fail!");
                return;
            }
            success(result[0], result[1], result[2], result[3]);
        }, fail);
    },

    decryptDataByFile:function(password, path, rootDir, destFileName, success, fail){
        InterfaceWrap.decryptDataByFile(password, path, rootDir, destFileName, success, fail);
    },

    decryptDataBySimpleFile:function(password, path, rootDir, destFileName, success, fail){
        cordova.plugins.secp256k1.decryptDataBySimpleFile(password, path, rootDir, destFileName, success, fail);
    },

    combineFile:function(path, header, destFileName, flag, success, fail){
        InterfaceWrap.combineFile(path, header, destFileName, flag, success, fail);
    },

    compressVideo:function(path, w, h, destPath, destFileName, success, fail){
        InterfaceWrap.compressVideo(path, w, h, destPath, destFileName, function(result){
            if(!result || result.length < 2){
                fail("json stringify list data fail!");
                return;
            }
            success(result[0], result[1]);
        }, fail);
    },

    compressAudio:function(path, destPath, destFileName, success, fail){
        InterfaceWrap.compressAudio(path, destPath, destFileName, function(result){
            if(!result || result.length < 2){
                fail("json stringify list data fail!");
                return;
            }
            success(result[0], result[1]);
        }, fail);
    },

    filePicker:function(success, fail){
        var callBack = function(result){
            if(success != null)
                success(result[0]);
        };
        window.OurCodeWorld.Filebrowser.filePicker.single({success:callBack, error:fail});
    },

    downloadFile:function(url, success, fail){
        InterfaceWrap.downloadFile(url, function(result){
            if(!result || result.length < 2){
                fail("json stringify list data fail!");
                return;
            }
            success(result[0], result[1]);
        }, fail);
    },

    clearCache:function(success, fail){
        cache.clear(success, fail);
    },

    vibrate:function(time){
        navigator.vibrate(0)
        navigator.vibrate(time);
    },

    notification:function(){
        navigator.notification.beep(1);
    },

    backToHomeScreen:function(success, fail){
        backAsHome.trigger(success, fail);
    },

    getCurrentLocale:function(success, fail){
        InterfaceWrap.getCurrentLocale(success, fail);
    },

    customRootDir:function(){
        return cordova.file.externalRootDirectory + "SafeEmail/";
    },

    hasRecordAudioPermission:function(success, fail){
        InterfaceWrap.hasRecordAudioPermission(success, fail);
    },

    hasExternalStoragePermission:function(success, fail){
        InterfaceWrap.hasExternalStoragePermission(success, fail);
    },

    requestExternalStoragePermission:function(success,fail){
        InterfaceWrap.requestExternalStoragePermission(success, fail);
    },

    requestAudioPermission:function(success,fail){
        InterfaceWrap.requestAudioPermission(success, fail);
    },

    getAudioDuration:function(path, success, fail){
        InterfaceWrap.getAudioDuration(path, success, fail);
    },

    enableBackgroundRunning:function(enterBackground, leaveBackground){
        var lang = (navigator.browserLanguage || navigator.language).toLowerCase().substr(0,2);
        cordova.plugins.backgroundMode.setDefaults({ text:lang=='zh'?"正在后台持续接收消息":"Receive message in the background", title:lang=='zh'?"安邮服务":"SafeEmail Service" });
        cordova.plugins.backgroundMode.enable();

        cordova.plugins.backgroundMode.on('activate', function() {
            cordova.plugins.backgroundMode.disableWebViewOptimizations();
            if(enterBackground)
                enterBackground();
        });

        cordova.plugins.backgroundMode.on('deactivate', function() {
            cordova.plugins.notification.local.cancelAll();
            if(leaveBackground)
                leaveBackground();
        });
    },

    backgroundModeIsActive:function(){
        return cordova.plugins.backgroundMode.isActive();
    },

    getFileLength:function(path, success, fail){
        InterfaceWrap.getFileLength(path, success, fail);
    },

    startInstallApk:function(path, success, fail){
        InterfaceWrap.startInstallApk(path, success, fail);
    },

    getVersionCode:function(success, fail){
        InterfaceWrap.getVersionCode(success, fail);
    },

    sendMessageNotification:function(count, sound, vibrate){
        if(count <= 0)
            count = 1;
        var lang = (navigator.browserLanguage || navigator.language).toLowerCase().substr(0,2);
        cordova.plugins.notification.local.schedule({
            title: lang=="zh"?'安邮':'SafeEmail',
            text: lang=="zh"?'收到新消息':'Receive new message',
            vibrate:vibrate,
            sound:sound,
            badge:count,
//            priority:-2,
            wakeup:false
        });
    },

    isIgnoringBatteryOptimizations:function(success, fail){
        InterfaceWrap.isIgnoringBatteryOptimizations(success, fail);
    },

    internetWhiteListRequest:function(success, fail){
        InterfaceWrap.internetWhiteListRequest(success, fail);
    },

    ECIESEncrypt:function(pubkey, data, success, fail){
        InterfaceWrap.ECIESEncrypt(pubkey, data, success, fail);
    },

    ECIESDecrypt:function(data, success, fail){
        InterfaceWrap.ECIESDecrypt(data, success, fail);
    },

    getHostConfig:function(success, fail){
        var defaultHost = "https://lu.changit.cn";
        var path =  cordova.file.externalApplicationStorageDirectory + "customhost.json";
        nativeInterfaceHelper.readFile(path, function(rawData){
            if(!rawData){
                success(defaultHost);
                return;
            }
            var data = g_convertToJSON(rawData);
            if(!data || !data.host){
                success(defaultHost);
                return;
            }
            success(data.host);
        }, function(err){
            success(defaultHost);
        });
    },

    getCurrentUserIndex:function(success, fail){
        InterfaceWrap.getCurrentUserIndex(success, fail);
    },

    setCurrentUserIndex:function(index, success, fail){
        InterfaceWrap.setCurrentUserIndex(index, success, fail);
    },

    addNewUser:function(data, success, fail){
        InterfaceWrap.addNewUser(data, success, fail);
    },

    generateNewUser:function(success, fail){
        InterfaceWrap.generateNewUser(success, fail);
    },

    generateSubKeyPair:function(success, fail){
        InterfaceWrap.generateSubKeyPair(success, fail);
    },

    removeUser:function(index, success, fail){
        InterfaceWrap.removeUser(index, success, fail);
    },

    modifyUserLabel:function(index, label, success, fail){
        InterfaceWrap.modifyUserLabel(index, label, success, fail);
    },

    modifyUserHost:function(index, host, success, fail){
        InterfaceWrap.modifyUserHost(index, host, success, fail);
    },
};

g_convertToJSON = function(str) {
    if (typeof str == 'string') {
        try {
            return JSON.parse(str);
        } catch(e) {
            return null;
        }
    }
    return null;
};

/*
** randomWord 产生任意长度随机字母数字组合
** randomFlag 是否任意长度 min 任意长度最小位[固定位数] max 任意长度最大位
** yuejingge 2017/11/8
*/

g_randomWord = function(randomFlag, min, max) {
    var str = "",
    range = min,
    arr = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
      'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
      'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
      'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
      '-','.','~','!','@','#','$','%','^','&','*','(',')','_',':','<','>','?'];

    if (randomFlag) {
        range = Math.round(Math.random() * (max - min)) + min;// 任意长度
    }
    for (var i = 0; i < range; i++) {
        pos = Math.round(Math.random() * (arr.length - 1));
        str += arr[pos];
    }
    return str;
};