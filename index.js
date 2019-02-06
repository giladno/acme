'use strict';
const crypto = require('crypto');
const net = require('net');
const util = require('util');
const axios = require('axios');
const forge = require('node-forge');

const generateKeyPair = util.promisify(forge.pki.rsa.generateKeyPair);

const sleep = timeout => new Promise(resolve => setTimeout(resolve, timeout));

const b64escape = s =>
    s
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

const b64encode = s => b64escape(Buffer.from(s).toString('base64'));

const pemBody = pem => pem.replace(/(\s*-----(BEGIN|END) ([A-Z0-9- ]+)-----|\r|\n)*/g, '');

module.exports = class ACME {
    static get letsencrypt() {
        return {
            staging: 'https://acme-staging-v02.api.letsencrypt.org/directory',
            production: 'https://acme-v02.api.letsencrypt.org/directory',
        };
    }

    constructor(directoryUrl, {accountKey, accountUrl} = {}) {
        Object.assign(this, {directoryUrl, accountKey, accountUrl});
        this.challenges = {
            'http-01': async ({url}) => await this.request({url}, {}),
        };
    }

    get jwk() {
        const privateKey = forge.pki.privateKeyFromPem(this.accountKey);
        return {
            e: b64encode(Buffer.from(forge.util.hexToBytes(privateKey.e.toString(16)), 'binary')),
            kty: 'RSA',
            n: b64encode(Buffer.from(forge.util.hexToBytes(privateKey.n.toString(16)), 'binary')),
        };
    }

    async request({url, name, ...opt}, payload) {
        if (name && !this.directory) {
            const {data} = await axios.get(this.directoryUrl);
            this.directory = data;
        }
        if (!url) url = this.directory[name];

        const {
            headers: {'replay-nonce': nonce},
        } = await axios.get(this.directory.newNonce);

        const data = {
            payload: payload && b64encode(JSON.stringify(payload)),
            protected: b64encode(
                JSON.stringify({
                    url,
                    alg: 'RS256',
                    nonce,
                    ...(this.accountUrl ? {kid: this.accountUrl} : {jwk: this.jwk}),
                })
            ),
        };

        data.signature = b64escape(
            crypto
                .createSign('RSA-SHA256')
                .update(`${data.protected}.${data.payload}`, 'utf8')
                .sign(this.accountKey, 'base64')
        );

        return await axios.request({
            method: 'POST',
            url,
            data,
            headers: {'content-type': 'application/jose+json'},
            ...opt,
        });
    }

    async createAccount({email, termsOfServiceAgreed = true, bits = 4096}) {
        const {privateKey} = await generateKeyPair({bits});
        this.accountKey = forge.pki.privateKeyToPem(privateKey);
        const {
            headers: {location: accountUrl},
        } = await this.request(
            {
                name: 'newAccount',
            },
            {
                termsOfServiceAgreed,
                contact: [].concat(email).map(e => `mailto:${e}`),
            }
        );
        this.accountUrl = accountUrl;
        return {accountUrl, accountKey: this.accountKey};
    }

    async updateAccount({email, termsOfServiceAgreed}) {
        await this.request(
            {url: this.accountUrl},
            {
                termsOfServiceAgreed,
                contact: email && [].concat(email).map(e => `mailto:${e}`),
            }
        );
    }

    async register({
        domain,
        commonName,
        country,
        state,
        locality,
        organization,
        organizationUnit,
        email,
        altNames = [],
        timeout = 60000,
        bits = 4096,
    }) {
        const domains = [].concat(domain);
        const {
            data: {authorizations = [], finalize},
            headers: {location},
        } = await this.request({name: 'newOrder'}, {identifiers: domains.map(value => ({type: 'dns', value}))});
        await Promise.all(
            authorizations.map(async url => {
                const {
                    data: {challenges = [], wildcard},
                } = await axios.get(url);
                return await Promise.all(
                    challenges.map(
                        async ({type, ...opt}) => this.challenges[type] && (await this.challenges[type](opt, wildcard))
                    )
                );
            })
        );

        for (const start = Date.now(); ; await sleep(1000)) {
            if (Date.now() - start >= timeout) throw new Error('timeout');
            const {
                data: {status},
            } = await axios.get(location);
            if (status == 'ready') break;
        }
        const csr = forge.pki.createCertificationRequest();
        const {privateKey, publicKey} = await generateKeyPair({bits});
        csr.publicKey = publicKey;

        csr.setSubject(
            Object.entries({
                CN: commonName || domains[0],
                C: country,
                ST: state,
                L: locality,
                O: organization,
                OU: organizationUnit,
                E: email,
            }).reduce((subject, [shortName, value]) => {
                if (value) subject.push({shortName, value});
                return subject;
            }, [])
        );
        if (altNames.length) {
            csr.setAttributes([
                {
                    name: 'extensionRequest',
                    extensions: [
                        {
                            name: 'subjectAltName',
                            altNames: altNames.map(value => ({type: net.isIP(value) ? 7 : 2, value})),
                        },
                    ],
                },
            ]);
        }
        csr.sign(privateKey);

        const {
            data: {certificate},
        } = await this.request(
            {url: finalize},
            {
                csr: b64escape(pemBody(forge.pki.certificationRequestToPem(csr))),
            }
        );
        const {data} = await this.request({url: certificate, responseType: 'text'}, '');
        const [cert, chain] = data
            .replace(/\r/g, '')
            .replace(/\n\n/g, '\n\r')
            .split(/\r/);
        return {privateKey: forge.pki.privateKeyToPem(privateKey), cert, chain};
    }

    async revoke(cert, reason) {
        await this.request({name: 'revokeCert'}, {certificate: b64escape(pemBody(cert)), reason});
    }

    middleware() {
        const prefix = '/.well-known/acme-challenge/';
        return (req, res, next) => {
            try {
                if (!req.url.startsWith(prefix)) return next();
                res.setHeader('Content-Type', 'text/plain; charset=utf-8');
                res.end(
                    `${req.url.slice(prefix.length)}.${b64escape(
                        crypto
                            .createHash('sha256')
                            .update(JSON.stringify(this.jwk))
                            .digest('base64')
                    )}`
                );
            } catch (err) {
                next(err);
            }
        };
    }
};
