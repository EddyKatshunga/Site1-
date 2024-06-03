function genererCle() {
    // Générer un tableau de 16 octets (correspondant à une clé AES de 128 bits)
    const keyBytes = new Uint8Array(16);
    crypto.getRandomValues(keyBytes);

    // Convertir le tableau d'octets en une chaîne hexadécimale
    const keyHex = Array.from(keyBytes).map(byte => ('0' + byte.toString(16)).slice(-2)).join('');

    return keyHex;
}
