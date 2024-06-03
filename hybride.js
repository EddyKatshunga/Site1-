// hybride.js

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

// Chiffrer le message avec un chiffrement hybride
async function chiffrerMessageHybride(message, clePubliqueBase64) {
    // Générer une clé AES
    const cleAES = await crypto.subtle.generateKey(
        { name: "AES-CBC", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
    
    const cleAESBytes = await crypto.subtle.exportKey("raw", cleAES);

    // Chiffrer la clé AES avec la clé publique RSA
    const clePubliqueBuffer = base64ToArrayBuffer(clePubliqueBase64);
    const clePublique = await crypto.subtle.importKey(
        "spki",
        clePubliqueBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
    );

    const cleAESChiffree = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        clePublique,
        cleAESBytes
    );

    // Chiffrer le message avec la clé AES
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const encodedMessage = new TextEncoder().encode(message);

    const messageChiffre = await crypto.subtle.encrypt(
        { name: "AES-CBC", iv: iv },
        cleAES,
        encodedMessage
    );

    // Combiner les données pour transmission
    const ivBase64 = arrayBufferToBase64(iv);
    const cleAESChiffreeBase64 = arrayBufferToBase64(cleAESChiffree);
    const messageChiffreBase64 = arrayBufferToBase64(messageChiffre);

    return ivBase64 + "." + cleAESChiffreeBase64 + "." + messageChiffreBase64;
}

// Déchiffrer le message avec un chiffrement hybride
async function dechiffrerMessageHybride(dataChiffree, clePriveeBase64) {
    const [ivBase64, cleAESChiffreeBase64, messageChiffreBase64] = dataChiffree.split(".");

    // Déchiffrer la clé AES avec la clé privée RSA
    const clePriveeBuffer = base64ToArrayBuffer(clePriveeBase64);
    const clePrivee = await crypto.subtle.importKey(
        "pkcs8",
        clePriveeBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["decrypt"]
    );

    const cleAESChiffreeBuffer = base64ToArrayBuffer(cleAESChiffreeBase64);
    const cleAESBytes = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        clePrivee,
        cleAESChiffreeBuffer
    );

    const cleAES = await crypto.subtle.importKey(
        "raw",
        cleAESBytes,
        { name: "AES-CBC" },
        false,
        ["decrypt"]
    );

    // Déchiffrer le message avec la clé AES
    const ivBuffer = base64ToArrayBuffer(ivBase64);
    const messageChiffreBuffer = base64ToArrayBuffer(messageChiffreBase64);

    const messageDechiffre = await crypto.subtle.decrypt(
        { name: "AES-CBC", iv: ivBuffer },
        cleAES,
        messageChiffreBuffer
    );

    return new TextDecoder().decode(messageDechiffre);
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
document.getElementById('genererCleRSA').addEventListener('click', genererCleRSA);

document.getElementById('chiffrer').addEventListener('click', async () => {
    const message = document.getElementById('message').value;
    const clePubliqueBase64 = document.getElementById('clePublique').value;
    const messageChiffre = await chiffrerMessageHybride(message, clePubliqueBase64);
    document.getElementById('messageChiffre').value = messageChiffre;
});

document.getElementById('dechiffrer').addEventListener('click', async () => {
    const messageChiffreBase64 = document.getElementById('messageChiffreDec').value;
    const clePriveeBase64 = document.getElementById('clePriveeDec').value;
    const messageDechiffre = await dechiffrerMessageHybride(messageChiffreBase64, clePriveeBase64);
    document.getElementById('messageDechiffre').value = messageDechiffre;
});
