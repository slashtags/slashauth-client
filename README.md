# slashtags-auth-client

## Installation

```bash
npm install @slashtags/slashauth-client
```

## Usage


```js
const { SlashAuthClient } = require('@slashtags/slashauth-client')
cosnt { generateKeyPair } = require('noise-curve-ed')

const keypair = generateKeyPair()
// use authServer's publicKey for pinning
const client = new SlashAuthClient({ keypair })

const response = await client.authz(slashauthURL)
// { status: 'ok', token: 'Bearer 123' }

const link = await client.magiclik(slashauthURL)
// { status: 'ok', ml: 'https://www.example.com?q=foobar' }

```

See https://github.com/slashtags/slashauth for server side implementation
