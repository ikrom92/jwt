import {createHmac, createSign, createVerify} from 'crypto'

export class Base64URL {

    static encode = (/** @type {Buffer|string} */data) => {
        if (typeof data === 'string') {
            data = Buffer.from(data)
        }
        return this.escape(data.toString('base64'))
    }

    static decode = (/** @type {string} */ data) => {
        return Buffer.from(this.unescape(data), 'base64')
    }

    static escape = (/**@type {string}*/base64) => {
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/[\=]+/,'')
    }

    static unescape = (/**@type {string}*/base64) => {
        return base64.replace(/\-/g, '+').replace(/\_/g, '/')
    }
}

export default class JWT {

    /**
     * 
     * @param {Header} header 
     * @param {Payload} payload 
     * @param {string} secret 
     */
    static generate = (header, payload, secret) => {
        const h = Base64URL.encode(JSON.stringify(header))
        const p = Base64URL.encode(JSON.stringify(payload))
        let s = null

        switch(header.alg) {
            case 'HS256': {
                const hmac = createHmac('SHA256', secret)
                s = Base64URL.encode(hmac.update(`${h}.${p}`).digest())
                break
            }
            case 'RS256': {
                const sign = createSign('RSA-SHA256')
                sign.update(`${h}.${p}`).end()
                s = Base64URL.escape(sign.sign(secret, 'base64'))
                break
            }
            default: throw new Error('Unsupported alg')
        }

        return `${h}.${p}.${s}`
    }

    /**
     * Throws an error if verification fails
     * @param {string} jwt 
     * @param {string} secret 
     * @returns {{header: Header, payload: Payload}}
     */
    static verify = (jwt, secret) => {
        
        const [h, p, s] = jwt.split('.')
        if (!h || !p || !s) {
            throw new Error('Invalid token syntax')
        }

        const header = JSON.parse(Base64URL.decode(h).toString())
        const payload = JSON.parse(Base64URL.decode(p).toString())
        
        let verified = false

        switch(header.alg) {
            case 'HS256': {
                const hmac = createHmac('SHA256', secret)
                verified = Base64URL.encode(hmac.update(`${h}.${p}`).digest()) == s
                break
            }
            case 'RS256': {
                const verify = createVerify('RSA-SHA256')
                verify.update(`${h}.${p}`).end()
                verified = verify.verify(secret, Buffer.from(s, 'base64'))
                break
            }
            default: throw new Error('Unsupported alg')
        }

        if (!verified) {
            throw new Error('Signature not verified')
        }
        
        return {header, payload}
    }

}

/**
 * @typedef Header
 * @property {string} alg HS256|RS256
 * @property {string} typ JWT
 */

 /**
  * @typedef Payload
  * @property {string=} iss Issuer
  * @property {string=} sub Subject
  * @property {string=} aud Audience
  * @property {number=} exp Expire date - number of seconds since 1970-01-01 00:00:00Z
  * @property {number=} iat Issued at - number of seconds since 1970-01-01 00:00:00Z
  */