const express = require('express');
const cors = require('cors');
const dns = require('dns').promises;
const whois = require('whois');
const fetch = require('node-fetch');
const geoip = require('geoip-lite');
const { parse: tldParse } = require('tldts');
const { promisify } = require('util');

const app = express();
const PORT = process.env.PORT || 3000;
const whoisLookup = promisify(whois.lookup);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('../')); // Отдаем фронтенд

// Очистка домена
function cleanDomain(domain) {
    return domain.replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/.*$/, '').toLowerCase().trim();
}

// Валидация домена
function isValidDomain(domain) {
    const pattern = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
    return pattern.test(domain);
}

// 1. Получение всех DNS записей
app.get('/api/dns/:domain', async (req, res) => {
    try {
        const domain = cleanDomain(req.params.domain);
        const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA', 'SRV'];
        const results = {};

        for (const type of types) {
            try {
                const records = await dns.resolve(domain, type);
                results[type] = records;
            } catch (err) {
                results[type] = null;
            }
        }

        res.json({ success: true, domain, dns: results });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 2. WHOIS информация
app.get('/api/whois/:domain', async (req, res) => {
    try {
        const domain = cleanDomain(req.params.domain);
        const rawData = await whoisLookup(domain);
        
        // Парсим важные поля
        const info = {
            registrar: extractField(rawData, /Registrar[:\s]*([^\n]+)/i),
            creationDate: extractField(rawData, /(?:Creation Date|Created On)[:\s]*([^\n]+)/i),
            expirationDate: extractField(rawData, /(?:Registry Expiry Date|Expiration Date|Expires On)[:\s]*([^\n]+)/i),
            updatedDate: extractField(rawData, /(?:Updated Date|Last Updated)[:\s]*([^\n]+)/i),
            nameServers: extractMultiple(rawData, /Name Server[:\s]*([^\n]+)/gi),
            status: extractMultiple(rawData, /(?:Domain )?Status[:\s]*([^\n]+)/gi),
            registrant: extractField(rawData, /(?:Registrant|Organization)[:\s]*([^\n]+)/i),
            country: extractField(rawData, /(?:Country|Registrant Country)[:\s]*([^\n]+)/i),
        };

        res.json({ success: true, domain, whois: info });
    } catch (error) {
        res.json({ 
            success: true, 
            domain: cleanDomain(req.params.domain), 
            whois: { error: 'WHOIS недоступен', details: error.message }
        });
    }
});

// 3. Поддомены через crt.sh
app.get('/api/subdomains/:domain', async (req, res) => {
    try {
        const domain = cleanDomain(req.params.domain);
        const response = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, {
            timeout: 10000
        });
        const data = await response.json();

        const subdomains = new Set();
        data.forEach(entry => {
            const name = entry.name_value?.toLowerCase();
            if (name && name.includes(domain)) {
                name.split('\n').forEach(n => {
                    const cleaned = n.trim().replace(/^\*\./, '');
                    if (cleaned && cleaned !== domain && cleaned.endsWith(domain)) {
                        subdomains.add(cleaned);
                    }
                });
            }
        });

        const sorted = [...subdomains].sort();
        res.json({ 
            success: true, 
            domain, 
            subdomains: sorted,
            count: sorted.length 
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 4. Сканирование портов
app.get('/api/ports/:domain', async (req, res) => {
    try {
        const domain = cleanDomain(req.params.domain);
        
        // Получаем IP домена
        const addresses = await dns.resolve4(domain);
        const ip = addresses[0];

        const commonPorts = [
            { port: 21, service: 'FTP' },
            { port: 22, service: 'SSH' },
            { port: 23, service: 'Telnet' },
            { port: 25, service: 'SMTP' },
            { port: 53, service: 'DNS' },
            { port: 80, service: 'HTTP' },
            { port: 110, service: 'POP3' },
            { port: 143, service: 'IMAP' },
            { port: 443, service: 'HTTPS' },
            { port: 993, service: 'IMAPS' },
            { port: 995, service: 'POP3S' },
            { port: 3306, service: 'MySQL' },
            { port: 5432, service: 'PostgreSQL' },
            { port: 8080, service: 'HTTP-Alt' },
            { port: 8443, service: 'HTTPS-Alt' },
            { port: 27017, service: 'MongoDB' },
        ];

        // Простая проверка через TCP connect
        const net = require('net');
        const results = [];

        for (const { port, service } of commonPorts) {
            const status = await checkPort(ip, port);
            results.push({ port, service, status });
        }

        res.json({ 
            success: true, 
            domain, 
            ip,
            ports: results 
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Проверка порта
function checkPort(host, port, timeout = 3000) {
    return new Promise((resolve) => {
        const net = require('net');
        const socket = new net.Socket();
        let status = 'closed';

        socket.setTimeout(timeout);
        socket.on('connect', () => {
            status = 'open';
            socket.destroy();
        });
        socket.on('timeout', () => {
            socket.destroy();
        });
        socket.on('error', () => {
            socket.destroy();
        });
        socket.on('close', () => {
            resolve(status);
        });

        socket.connect(port, host);
    });
}

// 5. Технологии сайта
app.get('/api/tech/:domain', async (req, res) => {
    try {
        const domain = cleanDomain(req.params.domain);
        
        // Пробуем HTTPS, затем HTTP
        let response;
        let protocol = 'https';
        
        try {
            response = await fetch(`https://${domain}`, { 
                timeout: 5000,
                redirect: 'follow',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            });
        } catch {
            try {
                response = await fetch(`http://${domain}`, { 
                    timeout: 5000,
                    redirect: 'follow',
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                });
                protocol = 'http';
            } catch {
                return res.json({ 
                    success: true, 
                    domain, 
                    tech: { error: 'Сайт недоступен' }
                });
            }
        }

        const headers = response.headers.raw();
        const html = await response.text();

        const technologies = {
            server: headers['server']?.[0] || null,
            poweredBy: headers['x-powered-by']?.[0] || null,
            cms: detectCMS(html, headers),
            javascript: detectJS(html),
            analytics: detectAnalytics(html),
            cdn: detectCDN(headers),
            security: {
                csp: !!headers['content-security-policy'],
                hsts: !!headers['strict-transport-security'],
                xframe: headers['x-frame-options']?.[0] || null,
                xss: headers['x-xss-protection']?.[0] || null,
                contentType: headers['x-content-type-options']?.[0] || null,
            },
            ssl: protocol === 'https',
            responseCode: response.status,
        };

        res.json({ success: true, domain, technologies });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 6. Геолокация и полная информация
app.get('/api/geo/:domain', async (req, res) => {
    try {
        const domain = cleanDomain(req.params.domain);
        const addresses = await dns.resolve4(domain);
        const geo = [];

        for (const ip of addresses) {
            const location = geoip.lookup(ip);
            geo.push({
                ip,
                country: location?.country || 'Unknown',
                region: location?.region || 'Unknown',
                city: location?.city || 'Unknown',
                ll: location?.ll || [0, 0],
                timezone: location?.timezone || 'Unknown',
            });
        }

        res.json({ success: true, domain, geo });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Полное сканирование (все сразу)
app.get('/api/scan/:domain', async (req, res) => {
    const domain = cleanDomain(req.params.domain);
    
    if (!isValidDomain(domain)) {
        return res.status(400).json({ success: false, error: 'Некорректный домен' });
    }

    try {
        const results = {
            domain,
            timestamp: new Date().toISOString(),
            dns: null,
            whois: null,
            subdomains: null,
            ports: null,
            technologies: null,
            geo: null,
        };

        // Параллельный сбор данных
        const promises = [
            dns.resolve(domain, 'A').then(() => fetch(`http://localhost:${PORT}/api/dns/${domain}`).then(r => r.json())).catch(() => null),
            fetch(`http://localhost:${PORT}/api/whois/${domain}`).then(r => r.json()).catch(() => null),
            fetch(`http://localhost:${PORT}/api/subdomains/${domain}`).then(r => r.json()).catch(() => null),
            fetch(`http://localhost:${PORT}/api/ports/${domain}`).then(r => r.json()).catch(() => null),
            fetch(`http://localhost:${PORT}/api/tech/${domain}`).then(r => r.json()).catch(() => null),
            fetch(`http://localhost:${PORT}/api/geo/${domain}`).then(r => r.json()).catch(() => null),
        ];

        const [dnsData, whoisData, subdomainsData, portsData, techData, geoData] = await Promise.allSettled(promises);

        results.dns = dnsData.value?.dns || null;
        results.whois = whoisData.value?.whois || null;
        results.subdomains = subdomainsData.value?.subdomains || [];
        results.ports = portsData.value?.ports || [];
        results.technologies = techData.value?.technologies || null;
        results.geo = geoData.value?.geo || [];

        res.json({ success: true, ...results });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Вспомогательные функции
function extractField(text, regex) {
    const match = text.match(regex);
    return match ? match[1].trim() : null;
}

function extractMultiple(text, regex) {
    const matches = text.match(regex);
    return matches ? matches.map(m => m.replace(regex, '$1').trim()) : [];
}

function detectCMS(html, headers) {
    const cms = [];
    if (html.includes('wp-content') || html.includes('wordpress')) cms.push('WordPress');
    if (html.includes('Joomla') || html.includes('joomla')) cms.push('Joomla');
    if (html.includes('Drupal') || html.includes('drupal')) cms.push('Drupal');
    if (html.includes('Shopify') || html.includes('shopify')) cms.push('Shopify');
    if (html.includes('Wix') || html.includes('wix')) cms.push('Wix');
    if (html.includes('Bitrix') || html.includes('bitrix')) cms.push('1C-Bitrix');
    return cms.length > 0 ? cms : ['Не определена'];
}

function detectJS(html) {
    const frameworks = [];
    if (html.includes('react') || html.includes('React')) frameworks.push('React');
    if (html.includes('vue') || html.includes('Vue')) frameworks.push('Vue.js');
    if (html.includes('angular') || html.includes('Angular')) frameworks.push('Angular');
    if (html.includes('jquery') || html.includes('jQuery')) frameworks.push('jQuery');
    return frameworks.length > 0 ? frameworks : ['Не определены'];
}

function detectAnalytics(html) {
    const analytics = [];
    if (html.includes('google-analytics') || html.includes('gtag')) analytics.push('Google Analytics');
    if (html.includes('yandex.metrika') || html.includes('ym.js')) analytics.push('Yandex Metrika');
    if (html.includes('facebook.com/tr')) analytics.push('Facebook Pixel');
    return analytics.length > 0 ? analytics : null;
}

function detectCDN(headers) {
    const cdn = [];
    if (headers['cf-ray']) cdn.push('Cloudflare');
    if (headers['x-cache']?.[0]?.includes('Hit')) cdn.push(headers['x-cache'][0]);
    if (headers['x-amz-cf-id']) cdn.push('AWS CloudFront');
    if (headers['x-sucuri-id']) cdn.push('Sucuri');
    return cdn.length > 0 ? cdn : null;
}

// Запуск сервера
app.listen(PORT, () => {
    console.log(`
    ╔══════════════════════════════════════╗
    ║     SUCDOM Backend запущен! 🚀     ║
    ║     Порт: ${PORT}                      ║
    ║     http://localhost:${PORT}           ║
    ╚══════════════════════════════════════╝
    
    Доступные API endpoints:
    GET /api/scan/:domain        - Полное сканирование
    GET /api/dns/:domain         - DNS записи
    GET /api/whois/:domain       - WHOIS инфо
    GET /api/subdomains/:domain  - Поддомены
    GET /api/ports/:domain       - Порты
    GET /api/tech/:domain        - Технологии
    GET /api/geo/:domain         - Геолокация
    `);
});
