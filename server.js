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
    const { url, fields } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'Missing url' });
    }
    const want = (Array.isArray(fields) && fields.length > 0)
        ? new Set(fields.map(f => String(f)))
        : null;
    try {
        const baseDomain = getBaseDomain(url);
        let data, ipv4, ipv6, isCloudflare, cmsData, isOldAsRocks, sslInfo, pageLoadTime, trackingSoftware;
        if (!want || want.has('data')) {
            data = await whois(baseDomain);
        }
        if (!want || want.has('ip') || want.has('isCloudflare')) {
            try {
                const addresses = await dns.lookup(baseDomain, { all: true });
                for (const addr of addresses) {
                    if (addr.family === 4 && !ipv4) ipv4 = addr.address;
                    if (addr.family === 6 && !ipv6) ipv6 = addr.address;
                }
            } catch (e) {}
        }
        if (!want || want.has('isCloudflare')) {
            isCloudflare = false;
            if (ipv4 && isIPInCloudflare(ipv4)) isCloudflare = true;
            if (ipv6 && isIPInCloudflare(ipv6)) isCloudflare = true;
        }
        if (!want || want.has('cmsData')) {
            cmsData = await detectCMS(url);
        }
        if (!want || want.has('isOldAsRocks')) {
            isOldAsRocks = false;
            let createdDate = (data && (data.creationDate || data['Creation Date'] || data['createdDate'] || data['created'])) || null;
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
        }
        if (!want || want.has('sslInfo')) {
            sslInfo = null;
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
        }
        if (!want || want.has('pageLoadTime') || want.has('trackingSoftware')) {
            pageLoadTime = null;
            trackingSoftware = [];
            try {
                const start = Date.now();
                const pageUrl = url.startsWith('http') ? url : 'https://' + url;
                const pageResp = await axios.get(pageUrl, {
                    timeout: 10000,
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36'
                    },
                    maxRedirects: 5,
                    validateStatus: null
                });
                pageLoadTime = Date.now() - start;
                if (pageResp && pageResp.data) {
                    const html = pageResp.data;
                    if (/www\.googletagmanager\.com\/gtag\/js|google-analytics\.com\/analytics\.js|ga\('create'|gtag\(/i.test(html)) {
                        trackingSoftware.push('Google Analytics');
                    }
                    if (/plausible\.io\/js\/plausible\.js/i.test(html)) {
                        trackingSoftware.push('Plausible');
                    }
                    if (/cdn\.segment\.com\/analytics\.js/i.test(html)) {
                        trackingSoftware.push('Segment');
                    }
                    if (/hotjar\.com\/c\/hotjar-/i.test(html)) {
                        trackingSoftware.push('Hotjar');
                    }
                    if (/clarity\.ms\/tag/i.test(html)) {
                        trackingSoftware.push('Microsoft Clarity');
                    }
                    if (/facebook\.net\/en_US\/fbevents\.js|connect\.facebook\.net\/en_US\/fbds\.js/i.test(html)) {
                        trackingSoftware.push('Facebook Pixel');
                    }
                    if (/announce\.layeredy\.com/i.test(html)) {
                        trackingSoftware.push('Layeredy Announce Analytics');
                    }
                }
            } catch (e) {
                pageLoadTime = null;
            }
        }
        const resp = { success: true };
        if (!want || want.has('data')) resp.data = data;
        if (!want || want.has('isCloudflare')) resp.isCloudflare = isCloudflare;
        if (!want || want.has('ip')) resp.ip = { ...(ipv4 && { ipv4 }), ...(ipv6 && { ipv6 }) };
        if (!want || want.has('cmsData')) resp.cmsData = cmsData;
        if (!want || want.has('isOldAsRocks')) resp.isOldAsRocks = isOldAsRocks;
        if (!want || want.has('sslInfo')) resp.sslInfo = sslInfo;
        if (!want || want.has('pageLoadTime')) resp.pageLoadTime = pageLoadTime;
        if (!want || want.has('trackingSoftware')) resp.trackingSoftware = trackingSoftware;
        res.json(resp);
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

fetchCloudflareRanges().then(() => {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
});
