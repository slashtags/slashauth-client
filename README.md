# slashtags-auth-client

## Installation

```bash
npm install @slashtags/slashauth-client
```

## Usage


```js
const { SlashAuthClient } = require('@slashtags/slashauth-client')
const { generateKeyPair } = require('noise-curve-ed')

const keypair = generateKeyPair()
// use authServer's publicKey for pinning
const client = new SlashAuthClient({ keypair })

const slashauthURL = 'slashauth:47mqszp49u9a1ticnki5mwgx417qbhgz6qtg1n67n9zou436rh9y/v0.1/auth?token=token&relay=http://localhost:3000
'
const response = await client.authz(slashauthURL)
// { status: 'ok', token: 'token' }

const link = await client.magiclik(slashauthURL)
// { status: 'ok', ml: 'https://www.example.com?q=foobar' }

```

See https://github.com/slashtags/slashauth for server side implementation
