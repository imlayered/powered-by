document.addEventListener('DOMContentLoaded', () => {
    const form = document.querySelector('.search-form');
    const input = document.querySelector('.search-input');
    const results = document.getElementById('results');
    const titleElement = document.querySelector('.title');
    const typewriterElem = document.getElementById('typewriter');
    const turnstileContainer = document.getElementById('turnstile-container');
    let turnstileWidgetId = null;
    let turnstileSitekey = null;
    let turnstileToken = null;
    
    // i removd the typewriter effect it bad
    titleElement.innerHTML = '<strong>Powered by</strong>';
    typewriterElem.innerHTML = 'Check information about a website in less than 30 seconds.';
    typewriterElem.style.display = 'block';
    typewriterElem.style.textAlign = 'center';
    typewriterElem.style.margin = '0 auto 1.2rem auto';
    typewriterElem.style.fontSize = '1.1rem';
    typewriterElem.style.color = '#888';
    typewriterElem.style.fontFamily = 'sans-serif';
    
    const originalTitle = titleElement.innerHTML;
    const originalSubtitle = typewriterElem.innerHTML;
    
    function resetUI() {
        titleElement.innerHTML = originalTitle;
        typewriterElem.innerHTML = originalSubtitle;
        typewriterElem.style.display = 'block';
        results.textContent = '';
    }
    
    input.addEventListener('input', () => {
        if (input.value.trim() === '') {
            resetUI();
        }
    });

    function addHelpIconClickEvent() {
        const helpIcon = document.querySelector('.help-icon');
        if (helpIcon) {
            helpIcon.style.cursor = 'pointer';
            helpIcon.style.color = '#007bff';
            helpIcon.addEventListener('click', () => {
                window.open('https://github.com/imlayered/powered-by/blob/main/extra-info/supported-softwares.md', '_blank');
            });
        }
    }

    fetch('/api/turnstile-sitekey')
        .then(r => r.ok ? r.json() : Promise.reject())
        .then(data => {
            if (data.sitekey && window.turnstile) {
                turnstileSitekey = data.sitekey;
                turnstileWidgetId = window.turnstile.render(turnstileContainer, {
                    sitekey: turnstileSitekey,
                    callback: token => { turnstileToken = token; },
                    'error-callback': () => { turnstileToken = null; },
                    theme: 'auto',
                });
            } else if (data.sitekey) {
                window.addEventListener('turnstile-loaded', () => {
                    turnstileSitekey = data.sitekey;
                    turnstileWidgetId = window.turnstile.render(turnstileContainer, {
                        sitekey: turnstileSitekey,
                        callback: token => { turnstileToken = token; },
                        'error-callback': () => { turnstileToken = null; },
                        theme: 'auto',
                    });
                }, { once: true });
            }
        })
        .catch(() => {});

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        results.textContent = 'Checking... (This should only take a few seconds)';
        titleElement.innerHTML = originalTitle;
        
        let url = input.value.trim();
        if (!url) {
            results.textContent = 'Please enter a URL.';
            return;
        }
        
        let displayUrl = url.replace(/^(https?:\/\/)/, '').replace(/\/$/, '');
        
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
        
        const body = { url };
        if (turnstileSitekey && turnstileToken) {
            body['cf-turnstile-response'] = turnstileToken;
        }
        try {
            const response = await fetchWithTimeout('/api/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
                timeout: 10000
            });
            const data = await response.json();
            if (turnstileSitekey && !data.success && data.error && (
                data.error.toLowerCase().includes('turnstile') ||
                data.error.toLowerCase().includes('captcha')
            )) {
                results.innerHTML = `<div style='background:#ffefc0;color:#a67c00;padding:0.7em 1em;margin-bottom:1em;border-radius:6px;font-size:1.02em;font-weight:500;'>${data.error}</div>`;
                if (turnstileWidgetId && window.turnstile) {
                    window.turnstile.reset(turnstileWidgetId);
                    turnstileToken = null;
                }
                return;
            }
            
            let warning = '';
            if (data.cmsData && data.cmsData.error) {
                warning = `<div style="background:#ffefc0;color:#a67c00;padding:0.7em 1em;margin-bottom:1em;border-radius:6px;font-size:1.02em;font-weight:500;">Some details may be unavailable as <strong>${displayUrl}</strong> blocked the request.</div>`;
            }
            
            if (data.success) {
                const whois = data.data;
                const registrar = whois.registrar || whois['Registrar'] || whois['registrarName'] || 'Unknown';
                let createdDate = whois.creationDate || whois['Creation Date'] || whois['createdDate'] || whois['created'] || '';
                const cmsData = data.cmsData || { cms: null };
                typewriterElem.style.display = 'none';
                if (cmsData.cms) {
                    let cmsDisplay = cmsData.cms;
                    if (typeof cmsData.cms === 'object' && cmsData.cms.name && cmsData.cms.url) {
                        cmsDisplay = `<a href="${cmsData.cms.url}" target="_blank" rel="noopener noreferrer" style="color:inherit;text-decoration:underline;" data-cms-link>${cmsData.cms.name}</a>`;
                    }
                    titleElement.innerHTML = `<strong>${displayUrl}</strong> is powered by <strong>${cmsDisplay}</strong>`;
                } else {
                    titleElement.innerHTML = `We can't determine what software/CMS <strong>${displayUrl}</strong> is using  <span class="help-icon" title="Click for more information">(?)</span>`;
                    setTimeout(addHelpIconClickEvent, 100);
                }
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
                    let ipLines = '';
                    if (data.ip.ipv4) ipLines += `<strong>IPv4:</strong> ${data.ip.ipv4}<br>`;
                    if (data.ip.ipv6) ipLines += `<strong>IPv6:</strong> ${data.ip.ipv6}<br>`;
                    if (ipLines) {
                        ipSection = `<div style='margin-bottom:0.5em;padding:0.5em 0;border-bottom:1px solid #eee;'><strong>IP</strong><br>${ipLines.replace(/<br>$/, '')}</div>`;
                    }
                }
                let cfSection = '';
                if (typeof data.isCloudflare === 'boolean') {
                    cfSection = `<div style='margin-bottom:0.5em;padding:0.5em 0;border-bottom:1px solid #eee;'><strong>Cloudflare</strong><br><strong>Behind Cloudflare:</strong> ${data.isCloudflare ? 'Yes' : 'No'}</div>`;
                }
                let cmsSection = '';
                if (cmsData.cms) {
                    let cmsDisplay = cmsData.cms;
                    if (typeof cmsData.cms === 'object' && cmsData.cms.name && cmsData.cms.url) {
                        cmsDisplay = `<a href="${cmsData.cms.url}" target="_blank" rel="noopener noreferrer" style="color:inherit;text-decoration:underline;" data-cms-link>${cmsData.cms.name}</a>`;
                    }
                    cmsSection = `<div style='margin-bottom:0.5em;padding:0.5em 0;border-bottom:1px solid #eee;'><strong>Software</strong><br><strong>CMS:</strong> ${cmsDisplay}</div>`;
                }
                results.innerHTML = warning + domainSection + cmsSection + cfSection + ipSection;
                // ssl
                if (data.sslInfo) {
                    results.innerHTML += `<div style='margin-bottom:0.5em;padding:0.5em 0;border-bottom:1px solid #eee;'><strong>SSL Certificate</strong><br>
                        <strong>Issuer:</strong> ${data.sslInfo.issuer || 'Unknown'}<br>
                        <strong>Valid From:</strong> ${data.sslInfo.valid_from || 'Unknown'}<br>
                        <strong>Valid To:</strong> ${data.sslInfo.valid_to || 'Unknown'}
                    </div>`;
                }
                // tracking/analytics
                if (Array.isArray(data.trackingSoftware) && data.trackingSoftware.length > 0) {
                    results.innerHTML += `<div style='margin-bottom:0.5em;padding:0.5em 0;border-bottom:1px solid #eee;'><strong>Tracking/Analytics</strong><br>
                        <strong>Detected:</strong> ${data.trackingSoftware.map(s => `<span style='border-radius:4px;padding:2px 7px;margin-right:4px;'>${s}</span>`).join(' ')}
                    </div>`;
                }
                // speeeeeed
                if (typeof data.pageLoadTime === 'number') {
                    results.innerHTML += `<div style='margin-bottom:0.5em;padding:0.5em 0;border-bottom:1px solid #eee;'><strong>Page Load Time</strong><br>
                        <strong>Time:</strong> ${data.pageLoadTime} ms
                    </div>`;
                }
                // cache 
                if (data.cached) {
                    let cacheMsg = data.cacheNote || '';
                    let cachedAgo = '';
                    if (data.data && data.data._cachedAt) {
                        const cachedAt = new Date(data.data._cachedAt);
                        const now = new Date();
                        const diffMs = now - cachedAt;
                        const diffMins = Math.floor(diffMs / 60000);
                        const diffHours = Math.floor(diffMins / 60);
                        if (diffHours > 0) {
                            cachedAgo = `${diffHours} hour${diffHours !== 1 ? 's' : ''}${diffMins % 60 > 0 ? `, ${diffMins % 60} min${diffMins % 60 !== 1 ? 's' : ''}` : ''}`;
                        } else {
                            cachedAgo = `${diffMins} min${diffMins !== 1 ? 's' : ''}`;
                        }
                    }
                    if (!cachedAgo) cachedAgo = 'recently';
                    const note = document.createElement('div');
                    note.style.fontSize = '0.98em';
                    note.style.color = '#888';
                    note.style.margin = '1.2em 0 0.2em 0';
                    note.style.textAlign = 'center';
                    note.style.cursor = 'help';
                    note.title = cacheMsg;
                    note.textContent = `Cached (${cachedAgo} ago)`;
                    results.appendChild(note);
                }
                const dinoImgId = 'dino-img-footer';
                let dino = document.getElementById(dinoImgId);
                if (dino) dino.remove();
                if (data.isOldAsRocks) {
                    dino = document.createElement('img');
                    dino.src = '/static/images/dino.png';
                    dino.alt = 'Dino';
                    dino.id = dinoImgId;
                    dino.style.display = 'block';
                    dino.style.margin = '2em auto 0 auto';
                    dino.style.maxWidth = '120px';
                    dino.style.opacity = '0.85';
                    dino.title = 'This domain is over 20 years old!';
                    results.appendChild(dino);
                }
            } else {
                results.textContent = 'Error: ' + (data.error || 'Unknown error');
            }
        } catch (err) {
            if (turnstileSitekey && (err.message.toLowerCase().includes('turnstile') || err.message.toLowerCase().includes('captcha'))) {
                results.innerHTML = `<div style='background:#ffefc0;color:#a67c00;padding:0.7em 1em;margin-bottom:1em;border-radius:6px;font-size:1.02em;font-weight:500;'>${err.message}</</div>`;
                if (turnstileWidgetId && window.turnstile) {
                    window.turnstile.reset(turnstileWidgetId);
                    turnstileToken = null;
                }
                return;
            }
            if (err.message === 'timeout') {
                results.textContent = 'No response';
            } else {
                results.textContent = 'Request failed: ' + err.message;
            }
        } finally {
            if (turnstileWidgetId && window.turnstile) {
                window.turnstile.reset(turnstileWidgetId);
                turnstileToken = null;
            }
        }
    });
});