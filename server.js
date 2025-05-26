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
        let ip;
        try {
            const addresses = await dns.lookup(baseDomain, { all: true });
            ip = addresses[0]?.address;
        } catch (e) {
            ip = null;
        }
        let isCloudflare = false;
        if (ip) {
            isCloudflare = isIPInCloudflare(ip);
        }
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
        if (isCloudflare) {
            res.json({ success: true, data, isCloudflare, cmsData, isOldAsRocks });
        } else {
            res.json({ success: true, data, isCloudflare, ip, cmsData, isOldAsRocks });
        }
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

fetchCloudflareRanges().then(() => {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
});
