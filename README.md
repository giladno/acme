# ACME

A simple ACME client for Node.js

## Installation

```
$ npm install @giladno/acme --save
```

## Usage

```js
const ACME = require('@giladno/acme');

let account;
const client = new ACME(ACME.letsencrypt.staging, account);

account = await client.createAccount({email: 'email@domain.com'}); // you might want to persist account

app.use(client.middleware()); // for expressjs based apps

const {privateKey, cert, chain} = await client.register({domain: ['domain.com']});
```

## TODO

-   [ ] Add method to update account key
-   [ ] Finish documentation
-   [ ] Add tests

## Contributing

PR's are more than welcome! You can also drop me a line at gilad@novik.ca

## License

MIT
