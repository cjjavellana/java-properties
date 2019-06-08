import { AESCBC } from '../src/crypto';
import { assert } from "chai";
import crypto from "crypto";

describe('AESCBC', () => {
    it('can decrypt with only aes key', () => {
        let aescbc = new AESCBC("MTIzNDU2Nzg5MGFiY2RlZg==");
        let encrypted = aescbc.encrypt("The quick brown fox jumped over the table");
        let decrypted = aescbc.decrypt(encrypted);
        assert.equal(decrypted, "The quick brown fox jumped over the table");
    });

    it('can decrypt with aes & iv', () => {
        let iv = Buffer.from(crypto.randomBytes(16));
        let aescbc = new AESCBC("MTIzNDU2Nzg5MGFiY2RlZg==", iv.toString('base64'));
        let encrypted = aescbc.encrypt("The quick brown fox jumped over the table");
        let decrypted = aescbc.decrypt(encrypted);
        assert.equal(decrypted, "The quick brown fox jumped over the table");
    });

    it('can encrypt with only aes key', () => {
        let aescbc = new AESCBC("MTIzNDU2Nzg5MGFiY2RlZg==");
        let encrypted = aescbc.encrypt("The quick brown fox jumped over the table");
        assert.notEqual(encrypted, "The quick brown fox jumped over the table");
    });

    it('can encrypt with aes & iv', () => {
        let iv = Buffer.from(crypto.randomBytes(16));
        let aescbc = new AESCBC("MTIzNDU2Nzg5MGFiY2RlZg==", iv.toString('base64'));
        let encrypted = aescbc.encrypt("The quick brown fox jumped over the table");
        assert.notEqual(encrypted, "The quick brown fox jumped over the table");
    });
});