// rsa.js

// Générer les clés RSA
async function genererCleRSA() {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );

    const clePublique = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const clePrivee = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

    document.getElementById("clePublique").value = arrayBufferToBase64(clePublique);
    document.getElementById("clePrivee").value = arrayBufferToBase64(clePrivee);
    document.getElementById("chiffrer").disabled = false;
}

// Chiffrer le message
async function chiffrerMessageRSA(message, clePubliqueBase64) {
    const clePubliqueBuffer = base64ToArrayBuffer(clePubliqueBase64);
    const clePublique = await crypto.subtle.importKey(
        "spki",
        clePubliqueBuffer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        false,
        ["encrypt"]
    );

    const encodedMessage = new TextEncoder().encode(message);
    const encryptedMessage = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        clePublique,
        encodedMessage
    );

    return arrayBufferToBase64(encryptedMessage);
}

// Déchiffrer le message
async function dechiffrerMessageRSA(messageChiffreBase64, clePriveeBase64) {
    const clePriveeBuffer = base64ToArrayBuffer(clePriveeBase64);
    const clePrivee = await crypto.subtle.importKey(
        "pkcs8",
        clePriveeBuffer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        false,
        ["decrypt"]
    );

    const encryptedMessageBuffer = base64ToArrayBuffer(messageChiffreBase64);
    const decryptedMessage = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        clePrivee,
        encryptedMessageBuffer
    );

    return new TextDecoder().decode(decryptedMessage);
}

// Utilitaires pour convertir entre ArrayBuffer et Base64
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// Gestion des événements
document.getElementById('genererCle').addEventListener('click', genererCleRSA);

document.getElementById('chiffrer').addEventListener('click', async () => {
    const message = document.getElementById('message').value;
    const clePubliqueBase64 = document.getElementById('clePublique').value;
    const messageChiffre = await chiffrerMessageRSA(message, clePubliqueBase64);
    document.getElementById('messageChiffre').value = messageChiffre;
});

document.getElementById('dechiffrer').addEventListener('click', async () => {
    const messageChiffreBase64 = document.getElementById('messageChiffreDec').value;
    const clePriveeBase64 = document.getElementById('clePriveeDec').value;
    const messageDechiffre = await dechiffrerMessageRSA(messageChiffreBase64, clePriveeBase64);
    document.getElementById('messageDechiffre').value = messageDechiffre;
});
