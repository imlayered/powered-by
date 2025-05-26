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
            html.includes('window.cookieconsent.initialise({'),
            html.includes('Coldfire'),
            html.includes('coldfire'),
            html.includes('<a class="silkyItem"')
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
        // Substack
        if (
            html.includes('<link rel="preconnect" href="https://substackcdn.com"') ||
            html.includes("service: 'substack-web'") ||
            /allowedTracingUrls:\s*\[.*substack(cdn)?\.com.*\]/.test(html) ||
            /https?:\/\/(.+\/)?substack(cdn)?\.com/.test(html)
        ) {
            return { cms: { name: 'Substack', url: 'https://substack.com' } };
        }
        // Google Sites
        if (
            html.includes('https://sites.google.com/new/?usp') ||
            html.includes('content="Google Sites"') ||
            html.includes('sites.google.com')
        ) {
            return { cms: { name: 'Google Sites', url: 'https://sites.google.com/' } };
        }
        // Wix
        if (
            html.includes('<!-- sentryOnLoad Setup Script -->') ||
            html.includes('<script defer="" src="https://static.parastorage.com/'),
            html.includes('wixui-')
        ) {
            return { cms: { name: 'Wix', url: 'https://wix.com' } };
        }
        // Carrd
        if (html.includes('window.CARRD_DISABLE_ANIMATION')) { // Carrd check is not great as they make their code impossible to read and find unique identifiers
            return { cms: { name: 'Carrd', url: 'https://carrd.co' } };
        }
        // Plex Store
        if (
            html.includes('Plex Store is made by Plex Development.'),
            html.includes('PlexStore'),
            html.includes('Plex Store'),
            html.includes('<!-- Site Visits This Month -->') ||
            html.includes('textContent = new Date().getFullYear();') ||
            html.includes('    const navbarBurgers = Array.prototype.slice.call(document.querySelectorAll('),
            html.includes('(%%__NONCE__%%) ') ||
            html.includes('console.groupEnd();')) {
            return { cms: { name: 'Plex Store', url: 'https://plexdevelopment.net/' } };
        }
        // Tebex
        if (
            html.includes('Removal of the Tebex footer violates our Terms & Conditions.'),
            html.includes('<script type="text/javascript" src="https://nsure.tebex.io/sdk.js">'),
            html.includes('<script defer src="https://js.tebex.io/v/1.js"></script>')) {
            return { cms: { name: 'Tebex', url: 'https://tebex.io/' } };
        }
        // CraftingStore
        if (
            html.includes('<script src="https://cdn.craftingstore.net/assets/shops/js/jquery.min.js" data-no-instant></script>'),
            html.includes('<script src="https://cdn.craftingstore.net/assets/shops/js/bootstrap.min.js" data-no-instant></script>'),
            html.includes('<script src="https://cdn.craftingstore.net/assets/shops/js/store.js" data-no-instant></script>')) {
            return { cms: { name: 'CraftingStore', url: 'https://craftingstore.net/' } };
        }
        // Weebly
        if (
            html.includes('<script type="text/javascript">_W.configDomain = "www.weebly.com";</script><script>_W.relinquish && _W.relinquish()</script>'),
            html.includes('<div class="weebly-footer"'),
            html.includes('Powered by <span class="link weebly-icon"></span>'),
            html.includes('Proudly powered by <a href="https://www.weebly.com/?utm_source=internal&utm_medium=footer&utm_campaign=2" href="_blank">Weebly</a>')) {
            return { cms: { name: 'Weebly', url: 'https://www.weebly.com/' } };
        }
        // Discourse
        if (
            html.includes('<link href="/stylesheets/discourse-details'),
            html.includes('<script defer src="/assets/plugins/discourse-local-dates'),
            html.includes('<link rel="preload" href="/assets/discourse'),
            html.includes('<link rel="preload" href="/assets/start-discourse'),
            html.includes('discourse-cdn.com')) {
            return { cms: { name: 'Discourse', url: 'https://www.discourse.org/' } };
        }
        // Flarum
        if (
            html.includes('<script id="flarum-json-payload'),
            html.includes('flarum.core.app.load(data);'),
            html.includes('var flarum')) {
            return { cms: { name: 'Flarum', url: 'https://flarum.org/' } };
        }
        // Vanilla
        if (
            html.includes('<title>Powered By Vanilla</title>'),
            html.includes('<script src="/applications/vanilla/js/'),
            html.includes('<script>window.__VANILLA_BUILD_SECTION__=')) {
            return { cms: { name: 'Vanilla-OSS', url: 'https://vanilla.higherlogic.com/' } };
        }
        // Squarespace
        if (
            html.includes('<!-- This is Squarespace. -->'),
            html.includes('squarespace-cdn.com'),
            html.includes('<script defer="true" src="https://static1.squarespace.com')) {
            return { cms: { name: 'Squarespace', url: 'https://www.squarespace.com/' } };
        }
        // Webflow
        if (
            html.includes('var Webflow = Webflow'),
            html.includes('Webflow.push(() => {'),
            html.includes('<!-- This site was built in Webflow.'),
            html.includes('<title>Made in Webflow</title>')) {
            return { cms: { name: 'Webflow', url: 'https://webflow.com/' } };
        }
        // Zyro
        if (
            html.includes('https://zyroassets'),
            html.includes('https://cdn.zyrosite.com')) {
            return { cms: { name: 'Zyro', url: 'https://easywithai.com/tools/zyro' } };
        }
        // Shopify
        if (
            html.includes('<link rel="dns-prefetch" href="//cdn.shopify.com"/>'),
            html.includes('<script data-source-attribution="shopify.dynamic_checkout.dynamic.init">'),
            html.includes('window.ShopifyAnalytics = window.ShopifyAnalytics')) {
            return { cms: { name: 'Shopify', url: 'https://www.shopify.com/' } };
        }
        // Odoo
        if (
            html.includes('<script id="web.layout.odooscript" type="text/javascript">'),
            html.includes('odoo.__session_info__ ='),
            html.includes('<meta name="generator" content="Odoo"/>')) {
            return { cms: { name: 'Odoo', url: 'https://www.odoo.com/' } };
        }
        // Drupal
        if (
            html.includes('<meta name="Generator" content="Drupal'),
            html.includes('<div data-drupal-messages-fallback class="hidden"></div>'),
            html.includes('data-drupal-selector="drupal-settings-json">')) {
            return { cms: { name: 'Drupal', url: 'https://new.drupal.org/home' } };
        }
        // Clientexec
        if (
            html.includes('var clientexec = {};'),
            html.includes('clientexec.sessionHash = '),
            html.includes('clientexec.dateFormat =')) {
            return { cms: { name: 'Clientexec', url: 'https://www.clientexec.com/' } };
        }
        // Notion
        if (
            html.includes('https://usenotioncms.com/proxy') ||
            html.includes('.notion-collection-page-properties {'),
            html.includes(',{"notion_data":{')) {
            return { cms: { name: 'Notion', url: 'https://www.notion.com/' } };
        }
        // more
        
        return { cms: null };
    } catch (error) {
        console.error(`Error fetching ${url}:`, error.message);
        return { cms: null, error: error.message };
    }
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
