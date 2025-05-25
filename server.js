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

// cms detection
async function detectCMS(url) {
    try {
        const fullUrl = url.startsWith('http') ? url : `https://${url}`;
        const response = await axios.get(fullUrl, {
            timeout: 10000,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        });
        
        const html = response.data;
        
        // WordPress
        if (
            html.includes('/wp-content/') || 
            html.includes('wp-block-') || 
            html.includes('wp-includes') ||
            html.includes('wp-json')
        ) {
            return { cms: { name: 'WordPress', url: 'https://wordpress.org' } };
        }
        
        // Ghost
        if (
            html.match(/data-ghost-[a-zA-Z0-9_-]+/i) ||
            html.match(/--ghost-[a-zA-Z0-9_-]+/i)
        ) {
            return { cms: { name: 'Ghost', url: 'https://ghost.org' } };
        }
        // WHMCS
        if (html.includes('whmcsBaseUrl = ""')) {
            return { cms: { name: 'WHMCS', url: 'https://www.whmcs.com/' } };
        }
        // Paymenter
        if (
            html.includes('<p class="text-sm">Powered by Paymenter</p>') ||
            html.includes('data-update-uri="/paymenter/update"')
        ) {
            return { cms: { name: 'Paymenter', url: 'https://paymenter.org/' } };
        }
        // Blesta
        if (
            html.includes('class="blesta"') ||
            html.includes('<p class="text-center m-3">Powered by <a href="http://www.blesta.com/">Blesta</a>, &copy; Phillips Data, Inc.</p>')
        ) {
            return { cms: { name: 'Blesta', url: 'https://www.blesta.com/' } };
        }
        // XenForo
        if (
            html.includes('data-xf-'),
            html.includes('/styles/default/xenforo/')
        ) {
            return { cms: { name: 'XenForo', url: 'https://xenforo.com' } };
        }
        // Invision Community
        if (
            html.includes('<a rel="nofollow" title="Invision Community" href="https://www.invisioncommunity.com/">Powered by <span translate="no">Invision Community</span></a>') ||
            html.includes('ipsOffCanvas') ||
            html.includes('data-ips-hidden-group') ||
            html.includes('ipsOffCanvas--search') ||
            html.includes('ipsDataItem_stats_number') ||
            html.includes('ipsDataItem_stats_type')
        ) {
            return { cms: { name: 'Invision Community', url: 'https://www.invisioncommunity.com/' } };
        }
        // NamelessMC
        const namelessChecks = [
            html.includes('<span class="item">Powered By <a href="https://namelessmc.com">NamelessMC</a></span>'),
            html.includes('<a class="ui small default button"'),
            html.includes("console.warn('Failed to initialise cookie consent, it may be blocked by your browser or a browser extension');") ||
            html.includes('window.cookieconsent.initialise({')
        ];
        const namelessCount = namelessChecks.filter(Boolean).length;
        if (namelessCount >= 2) { // only is included bc nameless has weird html and only 1 is unique enough
            return { cms: { name: 'NamelessMC', url: 'https://namelessmc.com' } };
        }
        // Pterodactyl
        if (
            html.includes('<p class="PteroFooter">') ||
            html.match(/© 2015 - 20.*Pterodactyl Software/)
        ) {
            return { cms: { name: 'Pterodactyl', url: 'https://pterodactyl.io' } };
        }
        // more
        
        return { cms: null };
    } catch (error) {
        console.error(`Error fetching ${url}:`, error.message);
        return { cms: null, error: error.message };
    }
}

// api
app.post('/api/check', async (req, res) => {
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
        
        const cmsData = await detectCMS(url);
        
        if (isCloudflare) {
            res.json({ success: true, data, isCloudflare, cmsData });
        } else {
            res.json({ success: true, data, isCloudflare, ip, cmsData });
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
