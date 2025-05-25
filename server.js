const express = require('express');
const whois = require('whois-json');
const cors = require('cors');
const path = require('path');
const axios = require('axios');
const IPCIDR = require('ip-cidr').default;
const dns = require('dns').promises;

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

// api for whois check
app.post('/api/whois', async (req, res) => {
    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'Missing url' });
    }
    try {
        const data = await whois(url);
        let ip;
        try {
            const addresses = await dns.lookup(url.replace(/^https?:\/\//, ''), { all: true });
            ip = addresses[0]?.address;
        } catch (e) {
            ip = null;
        }
        let isCloudflare = false;
        if (ip) {
            isCloudflare = isIPInCloudflare(ip);
        }
        if (isCloudflare) {
            res.json({ success: true, data, isCloudflare });
        } else {
            res.json({ success: true, data, isCloudflare, ip });
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
