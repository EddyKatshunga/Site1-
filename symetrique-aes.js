async function chiffrerMessage(message, cleHex) {
    const cleBytes = new Uint8Array(cleHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const cleCryptoKey = await crypto.subtle.importKey(
        'raw', 
        cleBytes, 
        { name: 'AES-CBC' }, 
        false, 
        ['encrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(16));
    const encodedMessage = new TextEncoder().encode(message);

    const encryptedMessage = await crypto.subtle.encrypt(
        { name: 'AES-CBC', iv: iv },
        cleCryptoKey,
        encodedMessage
    );

    const encryptedMessageBytes = new Uint8Array(encryptedMessage);
    const encryptedMessageHex = Array.from(encryptedMessageBytes).map(byte => ('0' + byte.toString(16)).slice(-2)).join('');
    const ivHex = Array.from(iv).map(byte => ('0' + byte.toString(16)).slice(-2)).join('');

    return ivHex + encryptedMessageHex;
}

async function dechiffrerMessage(messageChiffreHex, cleHex) {
    const cleBytes = new Uint8Array(cleHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const cleCryptoKey = await crypto.subtle.importKey(
        'raw', 
        cleBytes, 
        { name: 'AES-CBC' }, 
        false, 
        ['decrypt']
    );

    const ivHex = messageChiffreHex.slice(0, 32);
    const encryptedMessageHex = messageChiffreHex.slice(32);

    const iv = new Uint8Array(ivHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const encryptedMessageBytes = new Uint8Array(encryptedMessageHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

    const decryptedMessage = await crypto.subtle.decrypt(
        { name: 'AES-CBC', iv: iv },
        cleCryptoKey,
        encryptedMessageBytes
    );

    return new TextDecoder().decode(decryptedMessage);
}

document.getElementById('genererCle').addEventListener('click', () => {
    const cleHex = genererCle(); // Assurez-vous que genererCle() est bien défini dans generateur.js
    document.getElementById('cle').value = cleHex;
    document.getElementById('chiffrer').disabled = false;
});

document.getElementById('chiffrer').addEventListener('click', async () => {
    const message = document.getElementById('message').value;
    const cleHex = document.getElementById('cle').value;
    const messageChiffre = await chiffrerMessage(message, cleHex);
    document.getElementById('messageChiffre').value = messageChiffre;
});

document.getElementById('dechiffrer').addEventListener('click', async () => {
    const messageChiffreHex = document.getElementById('messageChiffreDec').value;
    const cleHex = document.getElementById('cleDec').value;
    const messageDechiffre = await dechiffrerMessage(messageChiffreHex, cleHex);
    document.getElementById('messageDechiffre').value = messageDechiffre;
});
