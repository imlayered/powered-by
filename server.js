const express = require('express');
const whois = require('whois-json');
const cors = require('cors');
const path = require('path');
const axios = require('axios');
const IPCIDR = require('ip-cidr').default;
const dns = require('dns').promises;
const { detectCMS } = require('./checks.js');

const app = express();
const PORT = process.env.PORT || 3002;

app.use(cors());
app.use(express.json());
// main
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// static
app.use('/static', express.static(path.join(__dirname, 'static')));

let cloudflareRanges = [];

// Fetch Cloudflare IP ranges on server start
async function fetchCloudflareRanges() {
    const v4 = await axios.get('https://www.cloudflare.com/ips-v4');
    const v6 = await axios.get('https://www.cloudflare.com/ips-v6');
    cloudflareRanges = [
        ...v4.data.split('\n').filter(Boolean),
        ...v6.data.split('\n').filter(Boolean)
    ];
    console.log('Cloudflare IP ranges loaded:', cloudflareRanges.length);
}

function isIPInCloudflare(ip) {
    return cloudflareRanges.some(range => {
        const cidr = new IPCIDR(range);
        return cidr.contains(ip);
    });
}

function getBaseDomain(url) {
    try {
        let domain = url.replace(/^https?:\/\//, '');
        domain = domain.split('/')[0];
        domain = domain.split(':')[0];
        const parts = domain.split('.');
        if (parts.length > 2) {
            return parts.slice(-2).join('.');
        }
        return domain;
    } catch {
        return url;
    }
}

// api
app.post('/api/check', async (req, res) => {
    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'Missing url' });
    }
    try {
        const baseDomain = getBaseDomain(url);
        const data = await whois(baseDomain);
        let ipv4 = null;
        let ipv6 = null;
        try {
            const addresses = await dns.lookup(baseDomain, { all: true });
            for (const addr of addresses) {
                if (addr.family === 4 && !ipv4) ipv4 = addr.address;
                if (addr.family === 6 && !ipv6) ipv6 = addr.address;
            }
        } catch (e) {
            // ignore
        }
        let isCloudflare = false;
        if (ipv4 && isIPInCloudflare(ipv4)) isCloudflare = true;
        if (ipv6 && isIPInCloudflare(ipv6)) isCloudflare = true;
        const cmsData = await detectCMS(url);
        // dino
        let isOldAsRocks = false;
        let createdDate = data.creationDate || data['Creation Date'] || data['createdDate'] || data['created'] || null;
        if (createdDate) {
            let created = new Date(createdDate);
            if (!isNaN(created)) {
                let now = new Date();
                let years = now.getFullYear() - created.getFullYear();
                let months = now.getMonth() - created.getMonth();
                if (months < 0) {
                    years--;
                    months += 12;
                }
                if (years >= 20) {
                    isOldAsRocks = true;
                }
            }
        }
        const ipResult = {};
        if (ipv4) ipResult.ipv4 = ipv4;
        if (ipv6) ipResult.ipv6 = ipv6;

        // ssl
        let sslInfo = null;
        try {
            const urlObj = new URL(url.startsWith('http') ? url : 'https://' + url);
            if (urlObj.protocol === 'https:') {
                const tls = require('tls');
                const net = require('net');
                sslInfo = await new Promise((resolve, reject) => {
                    const socket = tls.connect({
                        host: urlObj.hostname,
                        port: 443,
                        servername: urlObj.hostname,
                        rejectUnauthorized: false,
                        timeout: 5000
                    }, () => {
                        const cert = socket.getPeerCertificate();
                        if (cert && cert.issuer) {
                            resolve({
                                issuer: cert.issuer.O || cert.issuer.CN || cert.issuerName,
                                valid_from: cert.valid_from,
                                valid_to: cert.valid_to
                            });
                        } else {
                            resolve(null);
                        }
                        socket.end();
                    });
                    socket.on('error', () => resolve(null));
                    socket.on('timeout', () => {
                        socket.destroy();
                        resolve(null);
                    });
                });
            }
        } catch (e) {
            sslInfo = null;
        }

        // page
        let pageLoadTime = null;
        try {
            const start = Date.now();
            const pageUrl = url.startsWith('http') ? url : 'https://' + url;
            await axios.get(pageUrl, {
                timeout: 10000,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36' // generic ua to avoid blocking
                },
                maxRedirects: 5,
                validateStatus: null
            });
            pageLoadTime = Date.now() - start;
        } catch (e) {
            pageLoadTime = null;
        }

        res.json({ success: true, data, isCloudflare, ip: ipResult, cmsData, isOldAsRocks, sslInfo, pageLoadTime });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

fetchCloudflareRanges().then(() => {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
});
