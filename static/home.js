document.addEventListener('DOMContentLoaded', () => {
    const form = document.querySelector('.search-form');
    const input = document.querySelector('.search-input');
    const results = document.getElementById('results');
    const titleElement = document.querySelector('.title');
    const typewriterElem = document.getElementById('typewriter');
    
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

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        results.textContent = 'Checking...';
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
                    ipSection = `<div style='margin-bottom:0.5em;padding:0.5em 0;border-bottom:1px solid #eee;'><strong>IP</strong><br><strong>IP Address:</strong> ${data.ip}</div>`;
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
                
                results.innerHTML = domainSection + cmsSection + cfSection + ipSection;
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