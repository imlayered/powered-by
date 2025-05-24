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
});