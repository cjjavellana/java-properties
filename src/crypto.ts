import aesjs, { utils as aesUtils} from "aes-js";

export interface Encryptor {
    /**
     * Encrypts plaintext and returns a base64 encoded string
     * 
     * @param plaintext 
     */
    encrypt(plaintext: string): string
}

export interface Decryptor {
    /**
     * Decrypts the encrypted value and returns the plaintext
     * 
     * @param encrypted 
     */
    decrypt(encrypted: string): string
}

export class AESCBC implements Decryptor, Encryptor {
    
    private aeskey: string;
    private iv: Uint8Array;

    /**
     * 
     * @param aeskey A base64 encoded string of 
     *  128, 192, or 256 bits long
     * @param iv a base64 encoded string
     */
    constructor(aeskey: string, iv?:string) {
        this.aeskey = aeskey;
        this.iv = (iv) ? this.ivStringToUint8Array(iv) : this.defaultIVFromKey(this.aeskey);
    }

    private ivStringToUint8Array(iv: string): Uint8Array {
        let buff = Buffer.from(iv, 'base64');
        let plainTextKey = buff.toString('ascii');
        return aesUtils.utf8.toBytes(plainTextKey)
    }

    private defaultIVFromKey(aeskey: string): Uint8Array {
        let buff = Buffer.from(aeskey, 'base64');
        let plainTextKey = buff.toString('ascii');
        let keyInBytes = aesUtils.utf8.toBytes(plainTextKey);
        let derivedIV = new Array()
        for(let i = keyInBytes.length - 1; i >= 0; i--) {
            derivedIV.push(keyInBytes[i] + 1)
        }

        return new Uint8Array(derivedIV);
    }

    /**
     * 
     * @param encrypted A base64 encoded encrypted string
     */
    decrypt(encrypted: string): string {
        let buff = Buffer.from(encrypted, 'base64');
        let aesCbc = new aesjs.ModeOfOperation.cbc(aesUtils.utf8.toBytes(this.aeskey), Array.from(this.iv));
        let plainTextInBytes = aesCbc.decrypt(Uint8Array.from(buff));
        let unpaddedPlainText = aesjs.padding.pkcs7.strip(Uint8Array.from(plainTextInBytes));
        return new TextDecoder('utf-8').decode(unpaddedPlainText);
    }

    encrypt(plaintext: string): string {
        let plainTextInBytes = aesUtils.utf8.toBytes(plaintext);
        let paddedPlainTextBytes = aesjs.padding.pkcs7.pad(plainTextInBytes);
        let aesCbc = new aesjs.ModeOfOperation.cbc(aesUtils.utf8.toBytes(this.aeskey), Array.from(this.iv));
        let encryptedBytes = aesCbc.encrypt(paddedPlainTextBytes);
        let encryptedBuffer = Buffer.from(encryptedBytes);
        return encryptedBuffer.toString('base64');
    }
}
