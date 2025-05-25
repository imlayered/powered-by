const softwareList = [
    'WordPress',
    'Ghost',
    'XenForo',
    'NamelessMC',
    'WHMCS',
    'Pterodactyl'
];

const hostList = [
    'Cloudflare',
    'Hetzner',
    'DigitalOcean',
    'OVHCloud',
    'Akamai'
];

const typewriterElem = document.getElementById('typewriter');
const hostTypewriterElem = document.createElement('div');
hostTypewriterElem.id = 'host-typewriter';
hostTypewriterElem.style.display = 'block';
hostTypewriterElem.style.textAlign = 'center';
hostTypewriterElem.style.margin = '0 auto 1.2rem auto'; 
hostTypewriterElem.style.fontSize = '1.1rem';
hostTypewriterElem.style.color = '#888';
hostTypewriterElem.style.fontFamily = 'monospace'; 
hostTypewriterElem.style.width = '100%';
typewriterElem.insertAdjacentElement('afterend', hostTypewriterElem);

let swIndex = 0;
let charIndex = 0;
let isDeleting = false;
let delay = 80;

function syncedTypeWriter() {
    const software = softwareList[swIndex];
    const host = hostList[swIndex % hostList.length];
    const maxSoftwareLength = Math.max(...softwareList.map(s => s.length));
    const maxHostLength = Math.max(...hostList.map(s => s.length));
    let swDisplay, hostDisplay;
    if (!isDeleting) {
        swDisplay = software.substring(0, charIndex + 1);
        hostDisplay = host.substring(0, charIndex + 1);
        charIndex++;
        if (charIndex === Math.max(software.length, host.length)) {
            isDeleting = true;
            delay = 1200;
        } else {
            delay = 80;
        }
    } else {
        swDisplay = software.substring(0, charIndex - 1);
        hostDisplay = host.substring(0, charIndex - 1);
        charIndex--;
        if (charIndex === 0) {
            isDeleting = false;
            swIndex = (swIndex + 1) % softwareList.length;
            delay = 400;
        } else {
            delay = 40;
        }
    }
    typewriterElem.innerHTML = `<span style='font-family:monospace;display:inline-block;min-width:${maxSoftwareLength}ch;'>${swDisplay}</span>`;
    typewriterElem.style.display = 'block';
    typewriterElem.style.textAlign = 'center';
    typewriterElem.style.margin = '0 auto 0.5rem auto';
    hostTypewriterElem.innerHTML = `and hosted by <span style='font-family:monospace;display:inline-block;min-width:${maxHostLength}ch;'>${hostDisplay}</span>`;
    setTimeout(syncedTypeWriter, delay);
}

document.addEventListener('DOMContentLoaded', () => {
    syncedTypeWriter();

    const form = document.querySelector('.search-form');
    const input = document.querySelector('.search-input');
    const results = document.getElementById('results');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        results.textContent = 'Checking...';
        let url = input.value.trim();
        if (!url) {
            results.textContent = 'Please enter a URL.';
            return;
        }
        url = url.replace(/^(https?:\/\/)/, '').replace(/\/$/, '');
        const fetchWithTimeout = (resource, options = {}) => {
            const { timeout = 10000 } = options;
            return Promise.race([
                fetch(resource, options),
                new Promise((_, reject) =>
                    setTimeout(() => reject(new Error('timeout')), timeout)
                )
            ]);
        };
        try {
            const response = await fetchWithTimeout('/api/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url }),
                timeout: 10000
            });
            const data = await response.json();
            if (data.success) {
                const whois = data.data;
                const registrar = whois.registrar || whois['Registrar'] || whois['registrarName'] || 'Unknown';
                let createdDate = whois.creationDate || whois['Creation Date'] || whois['createdDate'] || whois['created'] || '';
                let domainSection = `<div style='margin-bottom:0.5em;padding:0.5em 0;border-bottom:1px solid #eee;'><strong>Domain</strong><br><strong>Registrar:</strong> ${registrar}`;
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
                        domainSection += `<br><strong>Domain Age:</strong> ${years} year${years !== 1 ? 's' : ''}${months > 0 ? `, ${months} month${months !== 1 ? 's' : ''}` : ''}`;
                        if (years < 1) {
                            domainSection += ` <span style='color:#c00;cursor:help;' title='This domain is younger than 1 year old which is an indicator for potential spam/scam.'>(New domain)</span>`;
                        } else if (years >= 10) {
                            domainSection += ` <span style='color:#090;cursor:help;' title='This domain has been around for more than 10 years, it may be more trustworthy than a new domain.'>(Old domain)</span>`;
                        }
                    }
                }
                domainSection += '</div>';
                let ipSection = '';
                if (!data.isCloudflare && data.ip) {
                    ipSection = `<div style='margin-bottom:0.5em;padding:0.5em 0;border-bottom:1px solid #eee;'><strong>IP</strong><br><strong>IP Address:</strong> ${data.ip}</div>`;
                }
                let cfSection = '';
                if (typeof data.isCloudflare === 'boolean') {
                    cfSection = `<div style='margin-bottom:0.5em;padding:0.5em 0;border-bottom:1px solid #eee;'><strong>Cloudflare</strong><br><strong>Behind Cloudflare:</strong> ${data.isCloudflare ? 'Yes' : 'No'}</div>`;
                }
                results.innerHTML = domainSection + cfSection + ipSection;
            } else {
                results.textContent = 'Error: ' + (data.error || 'Unknown error');
            }
        } catch (err) {
            if (err.message === 'timeout') {
                results.textContent = 'No response';
            } else {
                results.textContent = 'Request failed: ' + err.message;
            }
        }
    });
});