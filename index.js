const {
  checkForXSS,
  checkForSQLInjection,
  checkForCSRF,
  checkForCommandInjection,
  checkForFileInclusion,
  checkForIDOR,
  checkForUnvalidatedRedirects,
  checkForSSRF,
} = require("./utils/functions");
const axios = require("axios");
const cheerio = require("cheerio");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");

class WebsiteSecurityScanner {
  constructor(options = {}) {
    this.config = {
      timeout: options.timeout || 15000,
      userAgent: options.userAgent || 'Security Scanner 2.0',
      maxRetries: options.maxRetries || 3,
      delay: options.delay || 1000,
      reportDir: options.reportDir || path.join(__dirname, 'reports'),
      headers: options.headers || {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
      }
    };
    this.results = [];
    this.vulnerabilityStats = new Map();
  }

  async scanWebsite(url, options = {}) {
    const startTime = Date.now();
    const scanConfig = { ...this.config, ...options };
    const scanId = `scan_${Date.now()}`;
    
    const scanResult = {
      scanId,
      url,
      timestamp: new Date().toISOString(),
      vulnerabilities: [],
      errors: [],
      scanDuration: 0,
      status: 'started'
    };

    console.log(`🔍 Starting security scan for: ${url}`);
    console.log(`📋 Scan ID: ${scanId}`);
    
    try {
      this.validateUrl(url);
      const response = await this.fetchUrl(url, scanConfig);
      
      scanResult.response = {
        status: response.status,
        headers: response.headers,
        size: Buffer.byteLength(response.data, 'utf8')
      };

      this.analyzeResponseHeaders(response.headers, scanResult);
      
      if (response.status >= 400) {
        this.addError(scanResult, 'HTTP_ERROR', `Received ${response.status} status`, 'medium');
      }

      const $ = this.loadHtmlContent(response.data, scanResult);
      await this.runSecurityChecks($, url, response, scanResult, scanConfig);
      this.performContentAnalysis($, url, response, scanResult);
      
      scanResult.status = 'completed';
      scanResult.scanDuration = Date.now() - startTime;
      this.generateReport(scanResult, scanConfig);
      
      console.log(`✅ Scan completed in ${scanResult.scanDuration}ms`);
      this.printScanSummary(scanResult);
      
      return scanResult;

    } catch (error) {
      this.handleScanError(scanResult, startTime, error);
      return scanResult;
    }
  }

  async fetchUrl(url, config) {
    const axiosConfig = {
      url,
      method: 'get',
      timeout: config.timeout,
      headers: {
        'User-Agent': config.userAgent,
        ...config.headers
      },
      maxRedirects: 5,
      validateStatus: (status) => status < 500, // Don't throw on 4xx errors
    };

    return this.makeRequestWithRetry(axiosConfig, config.maxRetries, config.delay);
  }

  async makeRequestWithRetry(config, maxRetries, delay, retryCount = 0) {
    try {
      return await axios(config);
    } catch (error) {
      if (retryCount < maxRetries && this.isRetriableError(error)) {
        console.log(`🔄 Retry attempt ${retryCount + 1} for ${config.url}`);
        await this.sleep(delay * (retryCount + 1));
        return this.makeRequestWithRetry(config, maxRetries, delay, retryCount + 1);
      }
      throw error;
    }
  }

  isRetriableError(error) {
    return error.code === 'ECONNRESET' || 
           error.code === 'ETIMEDOUT' || 
           error.code === 'ECONNABORTED' ||
           (error.response && error.response.status >= 500);
  }

  loadHtmlContent(html, scanResult) {
    try {
      return cheerio.load(html);
    } catch (error) {
      this.addError(scanResult, 'HTML_PARSING_ERROR', `Failed to parse HTML: ${error.message}`, 'low');
      return cheerio.load('');
    }
  }

  async runSecurityChecks($, url, response, scanResult, config) {
    const securityChecks = [
      { name: 'XSS', func: checkForXSS, context: { $, url } },
      { name: 'SQL Injection', func: checkForSQLInjection, context: { $, url } },
      { name: 'CSRF', func: checkForCSRF, context: { $, url, response } },
      { name: 'Command Injection', func: checkForCommandInjection, context: { $, url } },
      { name: 'File Inclusion', func: checkForFileInclusion, context: { $, url } },
      { name: 'IDOR', func: checkForIDOR, context: { url, response } },
      { name: 'Unvalidated Redirects', func: checkForUnvalidatedRedirects, context: { $, url } },
      { name: 'SSRF', func: checkForSSRF, context: { $, url } }
    ];

    for (const { name, func, context } of securityChecks) {
      await this.executeSecurityCheck(name, func, context, scanResult);
    }
    
    this.checkDynamicParameters($, url, scanResult);
  }

  async executeSecurityCheck(name, checkFunction, context, scanResult) {
    try {
      console.log(`   🔎 [${name}] Running check...`);
      const result = await checkFunction(context);
      
      if (result?.vulnerable) {
        this.addVulnerability(scanResult, name, result);
        this.updateVulnerabilityStats(name);
      }
    } catch (error) {
      this.addError(scanResult, 'CHECK_ERROR', `${name} check failed: ${error.message}`, 'low');
    }
  }

  checkDynamicParameters($, url, scanResult) {
    const paramPatterns = [
      { pattern: /(id|user|account)=(\d+)/, type: 'NUMERIC_ID' },
      { pattern: /(file|page|include)=([^&]+)/, type: 'FILE_PARAM' },
      { pattern: /(redirect|url)=([^&]+)/, type: 'REDIRECT_PARAM' }
    ];
    
    $('a[href], form').each((i, element) => {
      const $el = $(element);
      const targetUrl = $el.attr('href') || $el.attr('action') || '';
      
      paramPatterns.forEach(({ pattern, type }) => {
        const match = targetUrl.match(pattern);
        if (match) {
          this.addVulnerability(scanResult, 'DYNAMIC_PARAM', {
            description: `Dynamic parameter detected (${type})`,
            severity: 'low',
            location: targetUrl,
            details: {
              parameter: match[1],
              value: match[2],
              vulnerability: this.getParameterVulnerability(type)
            }
          });
        }
      });
    });
  }

  getParameterVulnerability(type) {
    const vulnerabilities = {
      'NUMERIC_ID': 'Potential IDOR vulnerability',
      'FILE_PARAM': 'Potential LFI/RFI vulnerability',
      'REDIRECT_PARAM': 'Potential open redirect vulnerability'
    };
    return vulnerabilities[type] || 'Parameter manipulation vulnerability';
  }

  performContentAnalysis($, url, response, scanResult) {
    this.checkSensitiveInfo($, scanResult);
    this.checkInsecureForms($, scanResult);
    this.checkMixedContent($, url, scanResult);
    this.checkOutdatedLibraries($, scanResult);
    this.checkCookieSecurity($, response, scanResult);
    this.checkComments($, scanResult);
  }

  checkComments($, scanResult) {
    $('*').contents().filter((_, el) => el.type === 'comment').each((_, comment) => {
      const text = comment.data.toLowerCase();
      
      const sensitiveKeywords = [
        'todo', 'fixme', 'hack', 'password', 
        'api key', 'secret', 'token', 'credentials'
      ];
      
      sensitiveKeywords.forEach(keyword => {
        if (text.includes(keyword)) {
          this.addVulnerability(scanResult, 'SENSITIVE_COMMENT', {
            description: `Sensitive keyword found in HTML comment: ${keyword}`,
            severity: 'low',
            details: { comment: comment.data.trim().substring(0, 100) + '...' }
          });
        }
      });
    });
  }

  checkCookieSecurity($, response, scanResult) {
    const setCookieHeaders = response.headers['set-cookie'] || [];
    
    setCookieHeaders.forEach(cookie => {
      const missingFlags = [];
      
      if (!cookie.includes('HttpOnly')) missingFlags.push('HttpOnly');
      if (!cookie.includes('Secure')) missingFlags.push('Secure');
      if (!cookie.includes('SameSite')) missingFlags.push('SameSite');
      
      if (missingFlags.length > 0) {
        this.addVulnerability(scanResult, 'INSECURE_COOKIE', {
          description: `Cookie missing security flags: ${missingFlags.join(', ')}`,
          severity: 'high',
          details: { cookie: cookie.split(';')[0] }
        });
      }
    });
  }

  checkSensitiveInfo($, scanResult) {
    const sensitivePatterns = [
      { pattern: /(password|passwd|pwd)\s*[:=]\s*["']?(\w+)["']?/i, type: 'PASSWORD_EXPOSURE' },
      { pattern: /(api[_-]?key|access[_-]?key)\s*[:=]\s*["']?([a-z0-9]{20,})["']?/i, type: 'API_KEY_EXPOSURE' },
      { pattern: /(secret|token)\s*[:=]\s*["']?([a-z0-9]{32,})["']?/i, type: 'SECRET_EXPOSURE' },
      { pattern: /\b\d{4}[\s-]*\d{4}[\s-]*\d{4}[\s-]*\d{4}\b/, type: 'CREDIT_CARD_EXPOSURE' },
      { pattern: /(aws_access_key_id|aws_secret_access_key)\s*=\s*(\w+)/i, type: 'AWS_CREDENTIALS' }
    ];

    const pageText = $('body').text().replace(/\s+/g, ' ');
    
    sensitivePatterns.forEach(({ pattern, type }) => {
      const matches = pageText.match(pattern);
      if (matches) {
        this.addVulnerability(scanResult, type, {
          description: `Sensitive data exposure detected: ${type}`,
          severity: 'critical',
          details: { 
            match: matches[0],
            context: this.getContextSnippet(pageText, matches.index)
          }
        });
      }
    });
  }

  getContextSnippet(text, index, length = 50) {
    const start = Math.max(0, index - length);
    const end = Math.min(text.length, index + length);
    return text.substring(start, end).replace(/\s+/g, ' ');
  }

  checkInsecureForms($, scanResult) {
    $('form').each((i, form) => {
      const $form = $(form);
      const action = $form.attr('action');
      const method = $form.attr('method')?.toLowerCase() || 'get';
      
      if (method === 'post') {
        const csrfTokens = $form.find('input[name*="csrf"], input[name*="token"]').length;
        if (!csrfTokens) {
          this.addVulnerability(scanResult, 'MISSING_CSRF_TOKEN', {
            description: 'Form found without CSRF protection',
            severity: 'medium',
            details: { formAction: action }
          });
        }
      }
      
      if (action && action.startsWith('http://')) {
        this.addVulnerability(scanResult, 'INSECURE_FORM_SUBMISSION', {
          description: 'Form submitting over insecure HTTP',
          severity: 'high',
          details: { formAction: action }
        });
      }
    });
  }

  checkMixedContent($, url, scanResult) {
    if (url.startsWith('https://')) {
      const httpResources = [];
      
      $('img, script, link[rel="stylesheet"], iframe').each((i, element) => {
        const $el = $(element);
        const src = $el.attr('src') || $el.attr('href') || $el.attr('data-src');
        
        if (src && src.startsWith('http://')) {
          httpResources.push(src);
        }
      });
      
      if (httpResources.length > 0) {
        this.addVulnerability(scanResult, 'MIXED_CONTENT', {
          description: 'HTTP resources loaded on HTTPS page',
          severity: 'medium',
            details: { 
              count: httpResources.length,
              resources: httpResources.slice(0, 5) 
            }
        });
      }
    }
  }

  checkOutdatedLibraries($, scanResult) {
    const libraryPatterns = [
      { name: 'jQuery', pattern: /jquery(?:\.min)?\.js\?v=(\d+\.\d+\.\d+)|jquery-(\d+\.\d+\.\d+)(?:\.min)?\.js/i },
      { name: 'Bootstrap', pattern: /bootstrap(?:\.min)?\.(?:js|css)\?v=(\d+\.\d+\.\d+)|bootstrap-(\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)/i },
      { name: 'Angular', pattern: /angular(?:\.min)?\.js\?v=(\d+\.\d+\.\d+)|angular-(\d+\.\d+\.\d+)(?:\.min)?\.js/i },
      { name: 'React', pattern: /react(?:\.min)?\.js\?v=(\d+\.\d+\.\d+)|react-(\d+\.\d+\.\d+)(?:\.min)?\.js/i },
      { name: 'Vue', pattern: /vue(?:\.min)?\.js\?v=(\d+\.\d+\.\d+)|vue-(\d+\.\d+\.\d+)(?:\.min)?\.js/i }
    ];

    $('script, link[rel="stylesheet"]').each((i, element) => {
      const $el = $(element);
      const src = $el.attr('src') || $el.attr('href') || '';
      
      libraryPatterns.forEach(lib => {
        const match = src.match(lib.pattern);
        if (match) {
          const version = match[1] || match[2] || match[3];
          if (version) {
            this.addVulnerability(scanResult, 'OUTDATED_LIBRARY', {
              description: `Potentially outdated ${lib.name} version detected`,
              severity: 'low',
              details: { library: lib.name, version, source: src }
            });
          }
        }
      });
    });
  }

  analyzeResponseHeaders(headers, scanResult) {
    const securityHeaders = {
      'x-frame-options': { 
        description: 'Missing X-Frame-Options header',
        severity: 'medium' 
      },
      'x-content-type-options': { 
        description: 'Missing X-Content-Type-Options header',
        severity: 'low'
      },
      'x-xss-protection': { 
        description: 'Missing X-XSS-Protection header',
        severity: 'low'
      },
      'strict-transport-security': { 
        description: 'Missing HSTS header',
        severity: 'high'
      },
      'content-security-policy': { 
        description: 'Missing Content Security Policy header',
        severity: 'high'
      }
    };

    Object.entries(securityHeaders).forEach(([header, info]) => {
      if (!headers[header]) {
        this.addVulnerability(scanResult, 'MISSING_SECURITY_HEADER', {
          description: info.description,
          severity: info.severity,
          details: { header }
        });
      }
    });
  }

  handleScanError(scanResult, startTime, error) {
    scanResult.status = 'failed';
    scanResult.scanDuration = Date.now() - startTime;
    this.addError(scanResult, 'SCAN_ERROR', error.message, 'high');
    console.error(`❌ Scan failed for ${scanResult.url}:`, error.message);
  }

  generateReport(scanResult, config) {
    const reportDir = config.reportDir;
    const reportPath = path.join(reportDir, `security_report_${scanResult.scanId}.json`);
    
    try {
      if (!fs.existsSync(reportDir)) {
        fs.mkdirSync(reportDir, { recursive: true });
      }
      
      const reportData = {
        meta: {
          scannerVersion: "2.0",
          generatedAt: new Date().toISOString()
        },
        ...scanResult,
        summary: this.generateSummary(scanResult)
      };
      
      fs.writeFileSync(reportPath, JSON.stringify(reportData, null, 2));
      console.log(`📄 Report saved: ${reportPath}`);
    } catch (error) {
      console.error('Failed to save report:', error);
      this.addError(scanResult, 'REPORT_ERROR', `Failed to save report: ${error.message}`, 'low');
    }
  }

  generateSummary(scanResult) {
    const severityCounts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };
    
    scanResult.vulnerabilities.forEach(v => {
      if (severityCounts[v.severity]) {
        severityCounts[v.severity]++;
      }
    });
    
    return {
      totalVulnerabilities: scanResult.vulnerabilities.length,
      ...severityCounts,
      errorCount: scanResult.errors.length
    };
  }

  printScanSummary(scanResult) {
    const summary = this.generateSummary(scanResult);
    
    console.log('\n📊 SCAN SUMMARY');
    console.log('================');
    console.log(`URL: ${scanResult.url}`);
    console.log(`Duration: ${scanResult.scanDuration}ms`);
    console.log(`Status: ${scanResult.status}`);
    console.log('\nVulnerabilities by Severity:');
    console.log(`  🔴 Critical: ${summary.critical}`);
    console.log(`  🟠 High: ${summary.high}`);
    console.log(`  🟡 Medium: ${summary.medium}`);
    console.log(`  🟢 Low: ${summary.low}`);
    console.log(`  ❌ Errors: ${summary.errorCount}`);
    
    if (scanResult.vulnerabilities.length > 0) {
      console.log('\nTop Vulnerabilities:');
      scanResult.vulnerabilities
        .slice(0, 5)
        .forEach((vuln, index) => {
          console.log(`  ${index + 1}. [${vuln.severity.toUpperCase()}] ${vuln.type}: ${vuln.description}`);
        });
    }
  }

  addVulnerability(scanResult, type, data) {
    scanResult.vulnerabilities.push({
      type,
      description: data.description,
      severity: data.severity || 'medium',
      location: data.location || scanResult.url,
      details: data.details || {}
    });
  }

  addError(scanResult, type, message, severity) {
    scanResult.errors.push({
      type,
      message,
      severity: severity || 'medium'
    });
  }

  updateVulnerabilityStats(vulnerabilityType) {
    const count = this.vulnerabilityStats.get(vulnerabilityType) || 0;
    this.vulnerabilityStats.set(vulnerabilityType, count + 1);
  }

  validateUrl(url) {
    try {
      new URL(url);
    } catch (error) {
      throw new Error(`Invalid URL: ${url}`);
    }
    
    if (!url.startsWith('http')) {
      throw new Error('URL must use HTTP/HTTPS protocol');
    }
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async scanMultipleUrls(urls, options = {}) {
    const results = [];
    
    for (const url of urls) {
      console.log(`\n🌐 Scanning ${url}...`);
      const result = await this.scanWebsite(url, options);
      results.push(result);
      
      if (this.config.delay > 0) {
        await this.sleep(this.config.delay);
      }
    }

    return results;
  }
}

// Standalone function for convenience
async function scanWebsite(url, options = {}) {
  const scanner = new WebsiteSecurityScanner(options);
  return await scanner.scanWebsite(url, options);
}

// Export both the class and the function
module.exports = {
  scanWebsite,
  WebsiteSecurityScanner
};
