import JWT from './JWT.js'
import fs from 'fs'

const jwt1 = JWT.generate({
    alg: 'HS256',
    typ: 'JWT'
}, {
    sub: 'user1',
    name: 'John Doe'
}, 'a secret')

try {
    const decoded = JWT.verify(jwt1, 'a secret')
    console.log('Token verified', decoded)
}
catch(error) {
    console.error(error.message)
}

const publicKey = fs.readFileSync('./public.pem', 'utf8')
const privateKey = fs.readFileSync('./private.pem', 'utf8')
const jwt2 = JWT.generate({
    alg: 'RS256',
    typ: 'JWT'
}, {
    sub: 'user2',
    name: 'John Doe 2'
}, privateKey)

try {
    const decoded = JWT.verify(jwt2, publicKey)
    console.log('Token verified', decoded)
}
catch(error) {
    console.error(error.message)
}

setTimeout(() => {}, 10000)